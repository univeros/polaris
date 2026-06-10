# API Reference

The complete HTTP surface Polaris contributes to the host router, as
implemented through Phase 4. Every endpoint, its authentication requirement,
request contract, and response codes below are taken from the shipped domains
and verified by the functional test suite.

- **Base path & versioning:** none assumed. The module contributes relative,
  unversioned routes; mounting and API versioning (a `/v1` prefix, header or
  media-type negotiation) are the host's responsibility, not the module's.
- JSON in, JSON out. Every endpoint is a framework
  **Action → Input → Domain → Responder** quad.

## Conventions

### Envelopes

| Kind               | Status | Shape                                                              |
| ------------------ | ------ | ------------------------------------------------------------------ |
| Success            | 2xx    | `{"data": {...}}` (the generic-acceptance endpoints return `{"message": "..."}`) |
| Validation failure | 422    | `{"errors": ["...", "..."]}`                                       |
| Semantic failure   | 4xx    | `{"error": "<code>", "message": "..."}` plus optional context fields |

### Authentication schemes

| Scheme     | How                                                                  |
| ---------- | -------------------------------------------------------------------- |
| public     | No credentials. Only the paths in the public list below.             |
| bearer     | `Authorization: Bearer <access token>`. Everything else under `/auth`, `/orgs`, `/permissions`, `/users`. Failures are `401` with `{"error":"unauthorized","message":"Authentication is required."}` and a `WWW-Authenticate: Bearer` header. |
| mfa ticket | The short-lived `mfa_token` JWT returned by login when MFA is required (`purpose=login_mfa`). Accepted only by `/auth/mfa/challenge` and `/auth/mfa/verify`. |
| permission | bearer plus a declared permission key, resolved from the **database** (never from token claims) for the token's active org. Failures are `403`. |
| step-up    | bearer plus a recent strong authentication: `now - auth_time <= security.step_up.max_age`. Applies only to users with a confirmed MFA factor. A stale `auth_time` gets `401` `{"error":"step_up_required","message":"This operation requires a recent re-authentication.","step_up":"/auth/mfa/step-up"}` with `WWW-Authenticate: Bearer error="step_up_required"`. |

Public paths: `/auth/login`, `/auth/register`, `/auth/email/verify` (covers
`/resend`), `/auth/token/refresh`, `/auth/password/forgot`,
`/auth/password/reset`, `/auth/.well-known/jwks.json`, and the ticket-gated
`/auth/mfa/challenge` and `/auth/mfa/verify`.

### Cross-tenant guard

Every `/orgs/{id}...` endpoint requires the path org to be the caller's
**active org** (the token's `org` claim); a mismatch is
`403 {"error":"forbidden","message":"That organization is not your active organization."}`.
A `superadmin` (database-resolved) is exempt. Scope a session to an org with
`POST /auth/switch-org`.

### Access-token claims

```json
{
  "sub": "<user id>",
  "jti": "<token id>",
  "sid": "<session id>",
  "org": "<active org id or null>",
  "roles": ["owner"],
  "scope": ["org.read", "..."],
  "email_verified": true,
  "mfa": true,
  "amr": ["pwd", "otp"],
  "auth_time": 1765432100
}
```

`sid` is the refresh-token family: one family is one session. `mfa`, `amr`,
and `auth_time` describe how the user authenticated; they survive refresh and
switch-org, and step-up re-stamps `auth_time`. Resource servers may treat
`roles`/`scope` as a hint only; Polaris itself re-resolves authority from the
database on every permission check.

### Rate limits

Fixed-window budgets; over-limit responses are `429` with `Retry-After` and
`X-RateLimit-*` headers. The per-IP groups run before routing; the
authenticated budget is per user id and runs after token authentication. Hosts
override any group via `auth.rate_limits`.

| Group           | Default   | Keyed by | Endpoints                                                |
| --------------- | --------- | -------- | -------------------------------------------------------- |
| login           | 10 / 300s | IP       | `/auth/login`                                            |
| register        | 5 / 3600s | IP       | `/auth/register`                                         |
| password_forgot | 5 / 3600s | IP       | `/auth/password/forgot`                                  |
| token_refresh   | 60 / 60s  | IP       | `/auth/token/refresh`                                    |
| token_consume   | 10 / 300s | IP       | `/auth/email/verify*`, `/auth/password/reset`, `/auth/invites/accept` |
| mfa_send        | 5 / 600s  | IP       | `/auth/mfa/challenge`, `/auth/mfa/step-up/challenge`, sms/email enroll |
| mfa_confirm     | 10 / 300s | IP       | `/auth/mfa/verify`, `/auth/mfa/step-up`, totp/sms/email confirm |
| mfa_enroll      | 5 / 3600s | IP       | `/auth/mfa/totp/enroll`, `/auth/mfa/factors*`            |
| authenticated   | 600 / 60s | user id  | every authenticated request                              |

---

## Identity & session endpoints

| Method/Path                       | Auth    | Success | Notes                               |
| --------------------------------- | ------- | ------- | ----------------------------------- |
| `GET /auth/.well-known/jwks.json` | public  | 200     | JWKS document                       |
| `POST /auth/register`             | public  | 202     | enumeration-safe                    |
| `POST /auth/email/verify`         | public  | 200     | single-use token                    |
| `POST /auth/email/verify/resend`  | public  | 202     | enumeration-safe                    |
| `POST /auth/login`                | public  | 200     | tokens, or the MFA gate             |
| `POST /auth/token/refresh`        | public  | 200     | rotates the refresh token           |
| `POST /auth/logout`               | bearer  | 200     | revokes the current session         |
| `POST /auth/logout-all`           | bearer  | 200     | revokes every session               |
| `POST /auth/switch-org`           | bearer  | 200     | re-scopes the session to an org     |
| `GET /auth/sessions`              | bearer  | 200     | device list                         |
| `DELETE /auth/sessions/{id}`      | bearer  | 200     | revoke one owned session            |
| `POST /auth/password/forgot`      | public  | 202     | enumeration-safe                    |
| `POST /auth/password/reset`       | public  | 200     | single-use token, logout everywhere |
| `POST /auth/password/change`      | step-up | 200     | keeps the current session           |
| `GET /auth/me`                    | bearer  | 200     | the authenticated identity          |

### GET /auth/.well-known/jwks.json

Returns `{"keys":[{"kty":"RSA","use":"sig","alg":"...","kid":"...","n":"...","e":"..."}]}`.
During a key rotation the retiring public key stays listed for one access-TTL
window (see [key-rotation.md](key-rotation.md)).

### POST /auth/register

Body: `email` (required, RFC 5321, max 320 octets), `password` (required, must
satisfy the password policy), `display_name` (optional, max 120 chars).
Always `202` with a generic message whether or not the address was new (no
account-existence oracle); a verification email is sent for new accounts.
`422` lists validation failures. Emits `user.registered`.

### POST /auth/email/verify

Body: `token` (required). `200 {"message":"Email verified."}`, idempotent;
`400` for an invalid or expired token; `422` when missing. Emits
`user.email_verified` on the first verification.

### POST /auth/email/verify/resend

Body: `email` (required). Always `202` with a generic message; resends only
for a known, unverified account.

### POST /auth/login

Body: `email`, `password` (both required).

Without a confirmed MFA factor, `200`:

```json
{"data": {"access_token": "...", "token_type": "Bearer", "expires_in": 900,
          "refresh_token": "...",
          "user": {"id": "...", "email": "...", "email_verified": true}}}
```

With a confirmed factor, the password step does **not** open a session; `200`:

```json
{"data": {"mfa_required": true, "mfa_token": "<login_mfa ticket>",
          "factors": [{"id": "...", "type": "totp|sms|email", "default": true,
                       "label": "iPhone", "destination": "+1 *** *** 0101"}]}}
```

(`label` and `destination` appear only when set; `destination` is masked. The
factor-management list at `GET /auth/mfa/factors` uses the same shape plus a
`confirmed` flag.)

The client completes the gate via `/auth/mfa/challenge` + `/auth/mfa/verify`
(or directly `/auth/mfa/verify` for TOTP and recovery codes).

Failures: `401 invalid_credentials` for a wrong password, unknown account, or
a live lockout (indistinguishable on purpose); `403 email_unverified` (with a
`resend` pointer) when `auth.require_verified_email` is on;
`403 account_disabled`; `422` for missing fields. Repeated failures within the
lockout window lock the account for `auth.lockout.duration`. Emits
`user.logged_in` (no-MFA path), `user.login_failed`, `user.locked`.

### POST /auth/token/refresh

Body: `refresh_token` (required). `200` with a fresh `access_token` and (with
rotation on, the default) a **new** `refresh_token`; the presented one is
consumed. Replaying a rotated token revokes the whole family and returns
`401 invalid_grant` (reuse detection); expired or unknown tokens are also
`401 invalid_grant`. The refreshed access token re-resolves roles/scope from
the database and preserves `mfa`/`amr`/`auth_time` from the session. Emits
`auth.token_refreshed`, or `auth.refresh_reuse_detected` on replay.

### POST /auth/logout and POST /auth/logout-all

Empty body; the session (`sid`) or user (`sub`) comes from the token. `200`
with `{"data":{"status":"logged_out"}}` / `{"data":{"status":"logged_out_all"}}`.
Logout-all emits `auth.sessions_revoked` with the revoked-session count.

### POST /auth/switch-org

Body: `organization_id` (required). The caller must be an **active** member of
an active org. `200` with a fresh `access_token` carrying the new
`org`/`roles`/`scope`; the live session is re-pointed so refreshes stay
scoped. `404` for an unknown or soft-deleted org, `403` when not an active
member, `401 session_ended` when the session was revoked. Emits
`auth.org_switched`.

### GET /auth/sessions and DELETE /auth/sessions/{id}

`GET` returns
`{"data":{"sessions":[{"id","current","ip","user_agent","created_at","last_used_at"}]}}`,
the caller's active sessions with the current one flagged. `DELETE` revokes
one session the caller owns: `200 {"data":{"status":"revoked"}}`, or `404`
when the session does not exist or belongs to someone else (no cross-user
disclosure).

### POST /auth/password/forgot and POST /auth/password/reset

`forgot`: body `email`; always `202` generic. Emits
`user.password_reset_requested` for a known active account.
`reset`: body `token`, `new_password`. `200 {"data":{"status":"password_reset"}}`
and every session is revoked (logout everywhere); `401 invalid_token` for a
bad, expired, or replayed token; `422` for policy failures. Emits
`user.password_changed` (method `reset`).

### POST /auth/password/change

Step-up gated. Body: `current_password`, `new_password`. `200`
`{"data":{"status":"password_changed"}}`; every **other** session is revoked,
the caller's stays. `403 invalid_credentials` for a wrong current password,
`422` for policy failures. Emits `user.password_changed` (method `change`).

### GET /auth/me

`200` with
`{"data":{"id","email","email_verified","display_name","status","mfa_enforced","orgs","roles"}}`.

---

## MFA endpoints

| Method/Path                                | Auth       | Success | Notes                             |
| ------------------------------------------ | ---------- | ------- | --------------------------------- |
| `POST /auth/mfa/totp/enroll`               | bearer     | 200     | secret + otpauth URI + QR         |
| `POST /auth/mfa/totp/confirm`              | bearer     | 200     | recovery codes on first factor    |
| `POST /auth/mfa/sms/enroll`                | bearer     | 200     | sends a code                      |
| `POST /auth/mfa/sms/confirm`               | bearer     | 200     | recovery codes on first factor    |
| `POST /auth/mfa/email/enroll`              | bearer     | 200     | sends a code                      |
| `POST /auth/mfa/email/confirm`             | bearer     | 200     | recovery codes on first factor    |
| `POST /auth/mfa/challenge`                 | mfa ticket | 200     | send a login-gate code            |
| `POST /auth/mfa/verify`                    | mfa ticket | 200     | mints the real session            |
| `POST /auth/mfa/step-up/challenge`         | bearer     | 200     | send a step-up code               |
| `POST /auth/mfa/step-up`                   | bearer     | 200     | fresh access token, new auth_time |
| `POST /auth/mfa/recovery-codes/regenerate` | step-up    | 200     | fresh batch of 10                 |
| `GET /auth/mfa/factors`                    | bearer     | 200     | list factors                      |
| `PATCH /auth/mfa/factors/{id}`             | bearer     | 200     | label / default                   |
| `DELETE /auth/mfa/factors/{id}`            | step-up    | 200     | last-factor protection            |

### Enrollment

`totp/enroll` (empty body) returns
`{"data":{"factor_id","secret","otpauth_uri","qr_svg"}}`; the secret is shown
only here. `sms/enroll` takes `phone_e164` (E.164 format); `email/enroll`
takes an optional `email` (defaults to the account address). Both send a code
and return `{"data":{"factor_id","destination"}}` with the destination masked.
`429 rate_limited` when the per-destination/per-account send budget or resend
cooldown applies.

Every `*/confirm` takes `factor_id` + `code` and returns
`{"data":{"status":"confirmed","recovery_codes":[...]}}`; the ten recovery
codes appear **only** when this is the user's first confirmed factor (shown
once, stored hashed). `422 invalid_code` for a wrong, expired, exhausted, or
replayed code; `404` for an unknown or foreign factor. Emits `mfa.enrolled` on
the first confirmed factor.

### The login gate (mfa ticket)

`challenge` takes `factor_id` (sms/email factors only;
`422 unsupported_factor` for TOTP) and returns
`{"data":{"channel","destination"}}` with the destination masked;
`429 too_many_requests` under the resend cooldown. `verify` takes `code` plus
either `factor_id`, or no factor (the recovery-code path; `type: "recovery"`
also forces it). Success mints the real session:

```json
{"data": {"access_token": "...", "token_type": "Bearer", "expires_in": 900,
          "refresh_token": "..."}}
```

with `mfa=true`, `amr=["pwd","otp"]`, and a fresh `auth_time`.
`422 invalid_code` on failure. Emits `mfa.verified` + `user.logged_in` (and
`mfa.recovery_used` when a recovery code was spent); failures emit
`mfa.verify_failed`.

### Step-up

The same shape as the gate, on a live bearer session: `step-up/challenge`
sends a code, `step-up` verifies it and returns
`{"data":{"access_token","token_type"}}`: a fresh access token for the
**same** session with a new `auth_time` (no refresh-token rotation). Use it to
clear `401 step_up_required` on the gated routes. Emits
`mfa.step_up_completed`.

### Factor management

`GET /auth/mfa/factors` lists all factors (confirmed and pending) with masked
destinations. `PATCH` updates `label` and/or `default` (only a confirmed
factor can be the default; `422 invalid_state` otherwise). `DELETE` is
step-up gated and refuses to remove the last confirmed factor while MFA is
enforced for the user (`409 last_factor_protected`). Emits
`mfa.factor_removed`.

`recovery-codes/regenerate` (step-up gated, empty body) retires the old batch
and returns ten fresh plaintext codes once. Emits `mfa.recovery_regenerated`.

---

## Organization & RBAC endpoints

| Method/Path                               | Permission             | Success | Notes                       |
| ----------------------------------------- | ---------------------- | ------- | --------------------------- |
| `POST /orgs`                              | (verified email)       | 201     | caller becomes owner        |
| `GET /orgs`                               | bearer                 | 200     | caller's active memberships |
| `GET /orgs/{id}`                          | `org.read`             | 200     |                             |
| `PATCH /orgs/{id}`                        | `org.update`           | 200     | rename                      |
| `DELETE /orgs/{id}`                       | `org.delete` + step-up | 200     | soft delete                 |
| `GET /orgs/{id}/members`                  | `members.read`         | 200     | email gating, see below     |
| `PATCH /orgs/{id}/members/{userId}/roles` | `members.update`       | 200     | escalation + owner guards   |
| `PATCH /orgs/{id}/members/{userId}`       | `members.update`       | 200     | suspend / reactivate        |
| `DELETE /orgs/{id}/members/{userId}`      | `members.remove`       | 200     | owner guards                |
| `POST /orgs/{id}/invites`                 | `members.invite`       | 201     | escalation guard            |
| `GET /orgs/{id}/invites`                  | `members.invite`       | 200     | pending only                |
| `DELETE /orgs/{id}/invites/{inviteId}`    | `members.invite`       | 200     | revoke                      |
| `POST /auth/invites/accept`               | bearer                 | 200     | email must match            |
| `GET /orgs/{id}/roles`                    | `roles.read`           | 200     |                             |
| `POST /orgs/{id}/roles`                   | `roles.manage`         | 201     | escalation guard            |
| `PATCH /orgs/{id}/roles/{roleId}`         | `roles.manage`         | 200     | slug immutable              |
| `DELETE /orgs/{id}/roles/{roleId}`        | `roles.manage`         | 200     | templates protected         |
| `GET /permissions`                        | bearer                 | 200     | the catalog                 |

### POST /orgs

Body: `name` (required, 1-160 chars), `slug` (optional, `[a-z0-9-]`, max 160,
derived from the name when omitted). Requires a verified email
(`403 email_unverified` otherwise). `201` with
`{"data":{"id","name","slug","role":"owner"}}`; the system role templates
(owner/admin/member) are cloned into the org and the caller becomes its sole
owner. `409 conflict` on a taken slug. Emits `org.created`.

### GET /orgs, GET /orgs/{id}, PATCH /orgs/{id}, DELETE /orgs/{id}

`GET /orgs` lists `{"data":[{"id","name","slug"}]}` for the caller's active
memberships in active orgs. `GET /orgs/{id}` returns
`{"data":{"id","name","slug","status"}}`. `PATCH` renames (`name`, 1-160
chars) and emits `org.updated`. `DELETE` (step-up gated) soft-deletes:
`status=suspended`, every member's org authority disappears on their next
resolution, org-scoped sessions are revoked, pending invites die;
`200 {"data":{"deleted":true}}`. Emits `org.deleted`. A soft-deleted org reads
as `404` everywhere.

### GET /orgs/{id}/members

`{"data":[{"user_id","email","display_name","status","roles"}]}` with
`status` one of `active|invited|suspended`. **Email gating:** invited and
suspended members' emails are `null` unless the caller also holds
`members.invite`; active members' emails are always present.

### Member management

`PATCH .../members/{userId}/roles` takes `role_slugs` (array) and **replaces**
the member's roles; emits `member.roles_changed`.
`PATCH .../members/{userId}` takes `status: "active"|"suspended"`; suspending
immediately revokes the member's sessions scoped to this org; a still-invited
member cannot be suspended (`409`). Emits `member.status_changed`. `DELETE`
removes the membership and emits `member.removed`.

Shared invariants, enforced from database-resolved authority (never token
claims):

- **No escalation:** an actor may only grant roles/permissions they themselves
  hold (`403`). Superadmin is exempt.
- **Owners are protected:** only an owner (or superadmin) may modify, suspend,
  or remove an owner (`403`).
- **Last-owner protection:** the last (active) owner cannot be demoted,
  suspended, or removed (`409 conflict`). Absolute; even owners and
  superadmins cannot orphan an org.

### Invitations

`POST .../invites` takes `email` + `role_slugs`; the escalation guard applies
to the granted roles. `201` with
`{"data":{"id","email","role_slugs","expires_at"}}` (the pending list at
`GET .../invites` adds `created_at` and `invited_by`); the token is delivered
by email (via the `member.invited` event), never returned by the API. Re-inviting the same email rotates the token and extends the expiry (one
pending invite per email per org). `409` when the email is already an active
member; `422` when the address belongs to a suspended member.

`POST /auth/invites/accept` (any authenticated user) takes `token`. The
invitation's email must match the caller's account email (`403` on mismatch);
the token is single-use and expiring (`400` otherwise).
`200 {"data":{"organization_id"}}`; the caller becomes an active member with
exactly the invited roles. Emits `member.joined`.

### Roles

Role shape: `{"id","slug","name","description","is_system","permission_keys"}`.
`POST` requires `name`, `slug` (`[a-z0-9-]`, unique in the org), optional
`description`, and `permission_keys` (every key must exist in the catalog and
be held by the actor). `PATCH` updates `name`/`description`/`permission_keys`;
the slug is immutable and the org's cloned `owner` role cannot be edited.
`DELETE` removes a custom role (cascade-detaching it from members); the cloned
`owner`/`admin`/`member` templates cannot be deleted. The global `superadmin`
role is unreachable through org paths. Emit `role.created`, `role.updated`,
`role.deleted`.

### GET /permissions

`{"data":[{"key","description"}]}`: the full catalog (Polaris core plus any
host-contributed keys).

| Key              | Grants                                                   |
| ---------------- | -------------------------------------------------------- |
| `org.read`       | view the organization profile                            |
| `org.update`     | edit organization name and settings                      |
| `org.delete`     | delete the organization                                  |
| `members.read`   | list organization members                                |
| `members.invite` | send membership invitations                              |
| `members.update` | change a member's roles or suspend them                  |
| `members.remove` | remove a member from the organization                    |
| `roles.read`     | list roles                                               |
| `roles.manage`   | create, update and delete custom roles                   |
| `users.read`     | read user records (admin scope, superadmin only)         |
| `users.manage`   | disable and enable users (admin scope, superadmin only)  |
| `audit.read`     | read the organization's audit log                        |

Role templates: **owner** holds every org-scoped key; **admin** holds all of
them except `org.delete`; **member** holds `org.read`, `members.read`,
`roles.read`; **superadmin** (global, never listed under an org) holds the
full catalog for every org.

---

## User admin endpoints

| Method/Path                | Auth                              | Success | Notes                  |
| -------------------------- | --------------------------------- | ------- | ---------------------- |
| `GET /users/{id}`          | self, or `users.read`             | 200     |                        |
| `PATCH /users/{id}`        | self, or `users.manage`           | 200     | display name           |
| `POST /users/{id}/disable` | `users.manage` + step-up          | 200     | never self             |
| `POST /users/{id}/enable`  | `users.manage`                    | 200     | clears lockout         |
| `DELETE /users/{id}`       | self or `users.manage`, + step-up | 200     | anonymizing tombstone  |

User shape: `{"data":{"id","email","display_name","status"}}`.

- `GET`/`PATCH` allow self-access without any permission; reading or updating
  **another** user requires the admin-scoped key. The permission check runs
  before any existence check, so non-admins learn nothing about unknown ids.
  `PATCH` accepts `display_name` (max 120 chars).
- `disable` revokes every session and blocks login; disabling yourself is
  `409 conflict`. `enable` reactivates a disabled or locked account and clears
  the lockout counters; re-enabling a deleted tombstone is `409`.
- `DELETE` anonymizes: the email becomes a hash at `deleted.invalid`, the
  profile is nulled, the status disabled, every session revoked; the row
  survives as a tombstone for referential and audit integrity.

Emit `user.disabled`, `user.enabled`, `user.deleted`.
