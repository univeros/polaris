# Data Model

All tables are prefixed `auth_`, use **UUID v7** string primary keys, and carry
`created_at` / `updated_at` (UTC) unless noted. Entities live in
`src/Entity/` and are Cycle-annotated (`#[Entity]`, `#[Column]`); repositories
implement `Altair\Persistence\Contracts\RepositoryInterface`. Migrations live in
`database/migrations/` and are generated via `bin/altair db:migration-plan`.

> **Why UUID v7, not the skeleton's `primary` int?** Sequential ids leak tenant
> size and enable enumeration. v7 is time-ordered, so it indexes nearly as well
> as an auto-increment while staying opaque. Generated with `symfony/uid`.

---

## 1. Entity-relationship overview

```
                          ┌───────────────────┐
                          │  auth_users       │
                          │  (identity)       │
                          └─────────┬─────────┘
            ┌───────────────┬───────┼────────────┬──────────────┬───────────────┐
            │               │       │            │              │               │
   auth_memberships  auth_refresh_  auth_mfa_  auth_otp_   auth_recovery_  auth_password_
   (user⇄org)        tokens         factors    challenges  codes           resets / email_
            │        (sessions)                                            verifications
            │
   auth_membership_roles ── auth_roles ── auth_role_permissions ── auth_permissions
            │                   │
   auth_organizations ─────────┘ (org-scoped roles; org_id NULL = system role)
            │
   auth_invitations (pending members)

   auth_audit_log  (append-only security event trail)
```

Relationships:

- A **User** has many **Memberships**; a **Membership** binds one user to one
  **Organization** (`unique(user_id, organization_id)`).
- A **Membership** has many **Roles** (via `auth_membership_roles`); a **Role**
  has many **Permissions** (via `auth_role_permissions`).
- A **Role** belongs to an Organization, or is a **system role** when
  `organization_id IS NULL` (e.g. global `superadmin`).
- A **User** has many **RefreshTokens** (sessions/devices), **MfaFactors**,
  **OtpChallenges**, and **RecoveryCodes**.

---

## 2. Tables

### `auth_users` — the identity record

| Column                | Type                    | Notes                                                        |
| --------------------- | ----------------------- | ------------------------------------------------------------ |
| `id`                  | uuid (pk)               | v7                                                           |
| `email`               | string(320)             | **unique**, stored lowercased/normalized                     |
| `email_verified_at`   | datetime, nullable      | null until verified                                          |
| `password_hash`       | string(255), nullable   | Argon2id; nullable to allow passwordless-only users later    |
| `display_name`        | string(120), nullable   |                                                              |
| `status`              | enum                    | `active` \| `disabled` \| `locked`                           |
| `mfa_enforced`        | bool                    | per-user override of the global enforce policy               |
| `failed_login_count`  | int                     | reset on success                                             |
| `locked_until`        | datetime, nullable      | set by lockout policy                                        |
| `last_login_at`       | datetime, nullable      |                                                              |
| `created_at`/`updated_at` | datetime            |                                                              |

Indexes: `unique(email)`, `index(status)`.

**Identity-provider contract:** `CycleIdentityProvider::findOneBy()` returns the
row as an array including `email` and `password_hash`, so the framework's
`RepositoryIdentityValidator` (configured `username→email`, `hash→password_hash`)
can `password_verify()` against it unchanged.

### `auth_organizations` — tenant

| Column        | Type                | Notes                                  |
| ------------- | ------------------- | -------------------------------------- |
| `id`          | uuid (pk)           |                                        |
| `name`        | string(160)         |                                        |
| `slug`        | string(160)         | **unique**, URL-safe                   |
| `status`      | enum                | `active` \| `suspended`                |
| `created_by`  | uuid (fk users)     | becomes `owner`                        |
| `created_at`/`updated_at` | datetime|                                        |

Indexes: `unique(slug)`, `index(status)`.

### `auth_memberships` — user ⇄ org

| Column            | Type                  | Notes                                        |
| ----------------- | --------------------- | -------------------------------------------- |
| `id`              | uuid (pk)             |                                              |
| `user_id`         | uuid (fk users)       | `ON DELETE CASCADE`                          |
| `organization_id` | uuid (fk orgs)        | `ON DELETE CASCADE`                          |
| `status`          | enum                  | `invited` \| `active` \| `suspended`         |
| `invited_by`      | uuid, nullable        |                                              |
| `joined_at`       | datetime, nullable    |                                              |
| `created_at`/`updated_at` | datetime      |                                              |

Indexes: `unique(user_id, organization_id)`, `index(organization_id, status)`.

### `auth_roles`

| Column            | Type               | Notes                                            |
| ----------------- | ------------------ | ------------------------------------------------ |
| `id`              | uuid (pk)          |                                                  |
| `organization_id` | uuid, **nullable** | NULL ⇒ system/global role                        |
| `name`            | string(80)         |                                                  |
| `slug`            | string(80)         | unique **within** org (`unique(org_id, slug)`)   |
| `description`     | string(255), null  |                                                  |
| `is_system`       | bool               | system roles cannot be deleted/edited by tenants |

Seeded roles (see [rbac.md](rbac.md)): `owner`, `admin`, `member` (per-org
templates) and `superadmin` (system, `organization_id NULL`).

### `auth_permissions`

| Column        | Type          | Notes                                  |
| ------------- | ------------- | -------------------------------------- |
| `id`          | uuid (pk)     |                                        |
| `key`         | string(120)   | **unique**, e.g. `members.invite`      |
| `description` | string(255)   |                                        |

The permission catalog is seeded from a code-defined registry (single source of
truth) on migrate; see [rbac.md](rbac.md#permission-catalog).

### `auth_role_permissions` (join)

`role_id` (fk), `permission_id` (fk); **pk(role_id, permission_id)**;
`ON DELETE CASCADE` both sides.

### `auth_membership_roles` (join)

`membership_id` (fk), `role_id` (fk); **pk(membership_id, role_id)**;
`ON DELETE CASCADE`. This is what binds a user's roles *within a specific org*.

### `auth_refresh_tokens` — sessions / devices

The heart of the rotating-refresh strategy.

| Column            | Type                  | Notes                                                    |
| ----------------- | --------------------- | -------------------------------------------------------- |
| `id`              | uuid (pk)             |                                                          |
| `user_id`         | uuid (fk users)       | `ON DELETE CASCADE`                                      |
| `organization_id` | uuid, nullable        | active-org context the access token is scoped to         |
| `family_id`       | uuid                  | rotation lineage; shared across the whole rotation chain |
| `parent_id`       | uuid, nullable        | the token this one rotated from                          |
| `token_hash`      | string(64)            | **HMAC-SHA256** of the opaque secret (hex); never plaintext |
| `user_agent`      | string(255), nullable | device fingerprinting for the sessions list             |
| `ip`              | string(45), nullable  |                                                          |
| `expires_at`      | datetime              | absolute expiry (e.g. now + 30d)                        |
| `last_used_at`    | datetime, nullable    | updated on each rotation                                 |
| `revoked_at`      | datetime, nullable    | set on rotation, logout, or reuse-detection             |
| `revoked_reason`  | enum, nullable        | `rotated` \| `logout` \| `reuse_detected` \| `admin` \| `password_change` |
| `created_at`      | datetime              |                                                          |

Indexes: `unique(token_hash)`, `index(user_id, revoked_at)`, `index(family_id)`,
`index(expires_at)` (for the cleanup sweep).

**Reuse detection:** a refresh request presents a token; we hash and look it up.
If found but `revoked_at` is set (already rotated), an attacker is replaying a
stolen token → **revoke the entire `family_id`** and emit
`auth.refresh_reuse_detected`. See [flows.md](flows.md#token-refresh--rotation).

### `auth_mfa_factors`

| Column             | Type                   | Notes                                                  |
| ------------------ | ---------------------- | ------------------------------------------------------ |
| `id`               | uuid (pk)              |                                                        |
| `user_id`          | uuid (fk users)        | `ON DELETE CASCADE`                                     |
| `type`             | enum                   | `totp` \| `sms` \| `email`                             |
| `label`            | string(80), nullable   | e.g. "iPhone Authenticator"                            |
| `secret_encrypted` | text, nullable         | TOTP shared secret, **encrypted** (`Encrypter`)        |
| `phone_e164`       | string(20), nullable   | for `sms` factors (E.164)                              |
| `email`            | string(320), nullable  | for `email` factors (defaults to user email)           |
| `is_default`       | bool                   | preferred factor when multiple exist                   |
| `confirmed_at`     | datetime, nullable     | unconfirmed factors can't satisfy MFA                  |
| `last_used_at`     | datetime, nullable     |                                                        |
| `created_at`/`updated_at` | datetime        |                                                        |

Indexes: `index(user_id, type)`, `index(user_id, confirmed_at)`.

### `auth_otp_challenges` — transient SMS/email OTP + MFA tickets

| Column         | Type                  | Notes                                                          |
| -------------- | --------------------- | ------------------------------------------------------------- |
| `id`           | uuid (pk)             |                                                               |
| `user_id`      | uuid (fk users)       |                                                               |
| `factor_id`    | uuid, nullable        | the factor being challenged (sms/email)                       |
| `purpose`      | enum                  | `login_mfa` \| `enroll` \| `password_reset` \| `email_verify` \| `step_up` |
| `channel`      | enum                  | `sms` \| `email` \| `totp`                                    |
| `code_hash`    | string(64), nullable  | HMAC-SHA256 of the numeric code (null for `totp`, verified live) |
| `destination`  | string(320), nullable | masked in responses; phone/email actually sent to             |
| `attempts`     | int                   | incremented per verify try                                    |
| `max_attempts` | int                   | default 5                                                     |
| `expires_at`   | datetime              | e.g. now + 5m                                                 |
| `consumed_at`  | datetime, nullable    | single-use                                                    |
| `ip`           | string(45), nullable  |                                                               |
| `created_at`   | datetime              |                                                               |

Indexes: `index(user_id, purpose, consumed_at)`, `index(expires_at)`.

> The short-lived **`mfa_token`** returned by `/auth/login` when MFA is required
> is itself a signed, single-purpose JWT (`purpose=login_mfa`, ~5 min) — *not* a
> DB row — that references the user; the OTP challenge row holds the actual code.

### `auth_recovery_codes`

`id`, `user_id` (fk), `code_hash` (HMAC-SHA256), `used_at` (nullable),
`created_at`. Index `index(user_id, used_at)`. Generated in batches of 10; each
is single-use; regenerating invalidates the prior batch.

### `auth_email_verifications` & `auth_password_resets`

Identical shape (single-use, hashed token):

| Column        | Type               | Notes                              |
| ------------- | ------------------ | ---------------------------------- |
| `id`          | uuid (pk)          |                                    |
| `user_id`     | uuid (fk users)    |                                    |
| `email`       | string(320)        | the address being verified/reset   |
| `token_hash`  | string(64)         | HMAC-SHA256 of the emailed token   |
| `expires_at`  | datetime           | verify: 24h, reset: 1h             |
| `consumed_at` | datetime, nullable | single-use                         |
| `ip`          | string(45), null   |                                    |
| `created_at`  | datetime           |                                    |

> Email verification and password reset support **both** a click link (opaque
> token) and a 6-digit OTP code path, sharing this table; the OTP path reuses
> `auth_otp_challenges` with `purpose=email_verify`/`password_reset`. Hosts pick
> one via config (`flows.email_verification.style: link | otp`).

### `auth_invitations`

| Column            | Type               | Notes                                  |
| ----------------- | ------------------ | -------------------------------------- |
| `id`              | uuid (pk)          |                                        |
| `organization_id` | uuid (fk orgs)     |                                        |
| `email`           | string(320)        | invitee (may not yet be a user)        |
| `role_ids`        | json               | roles to grant on acceptance           |
| `token_hash`      | string(64)         | HMAC-SHA256 of the emailed invite token|
| `invited_by`      | uuid (fk users)    |                                        |
| `expires_at`      | datetime           | default 7d                             |
| `accepted_at`     | datetime, nullable |                                        |
| `created_at`      | datetime           |                                        |

Index: `index(organization_id)`, `index(email)`, `unique(token_hash)`.

### `auth_audit_log` — append-only security trail

| Column            | Type               | Notes                                              |
| ----------------- | ------------------ | -------------------------------------------------- |
| `id`              | uuid (pk)          |                                                    |
| `actor_user_id`   | uuid, nullable     | who triggered it (null for anonymous attempts)     |
| `organization_id` | uuid, nullable     | org context if any                                 |
| `event`           | string(80)         | mirrors the PSR-14 event name ([events.md](events.md)) |
| `ip`              | string(45), null   |                                                    |
| `user_agent`      | string(255), null  |                                                    |
| `metadata`        | json               | event-specific, **never** secrets                  |
| `created_at`      | datetime           |                                                    |

Indexes: `index(actor_user_id, created_at)`, `index(event, created_at)`,
`index(organization_id, created_at)`. Written by a PSR-14 listener subscribing to
the domain events — not inline in domain services — so auditing stays a
cross-cutting concern.

---

## 3. Retention & cleanup

A scheduled command (`bin/altair` job, or host cron) prunes expired transient
rows so the tables stay small:

- `auth_otp_challenges`: delete `consumed_at IS NOT NULL OR expires_at < now()`.
- `auth_refresh_tokens`: delete `expires_at < now() - grace` (keep recently
  revoked for reuse-detection forensics, e.g. 7-day grace).
- `auth_email_verifications` / `auth_password_resets`: delete consumed/expired.
- `auth_audit_log`: retained per host policy (default 1 year), then archived.

A `Univeros\Polaris\Domain\Maintenance\PruneExpiredService` exposes this; the host wires
it to its scheduler. (Polaris does not assume a scheduler exists.)

---

## 4. Migration set

One migration per table (generated, never hand-written — see the Altair skill).
Ordering respects FKs:

```
0001_create_auth_users
0002_create_auth_organizations
0003_create_auth_memberships
0004_create_auth_roles
0005_create_auth_permissions
0006_create_auth_role_permissions
0007_create_auth_membership_roles
0008_create_auth_refresh_tokens
0009_create_auth_mfa_factors
0010_create_auth_otp_challenges
0011_create_auth_recovery_codes
0012_create_auth_email_verifications
0013_create_auth_password_resets
0014_create_auth_invitations
0015_create_auth_audit_log
0016_seed_permissions_and_system_roles   (data migration from the code registry)
```

Generate with `bin/altair db:migration-plan` (runs NOT-NULL / FK / unique safety
checks against the live DB), then `bin/altair db:migrate`.
