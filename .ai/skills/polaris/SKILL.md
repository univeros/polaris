---
name: polaris
description: Integrate and operate univeros/polaris, the authentication, MFA/OTP, and multi-tenant RBAC module for the univeros framework. Use when registering the module in a host app, configuring its secrets and ports, calling its HTTP API (login, tokens, MFA, orgs, members, roles), or reasoning about its token model and tenant invariants.
---

# Polaris: auth, MFA, and multi-tenant RBAC

Polaris is a self-contained univeros module. A host registers one class and
gets identity, sessions, MFA, organizations, members, invitations, roles, and
a permission system, contributed as routes, entities, migrations, middleware,
and PSR-14 events. Everything below reflects the implemented surface; the
deep references are in `docs/auth/` (start with `docs/auth/README.md`).

## 1. Registration

```php
// config/modules.php in the host
return [
    \Univeros\Polaris\Module::class,
];
```

`Module::apply()` builds and binds validated configuration eagerly (boot fails
fast on a missing secret) and delegates the container wiring to one binder per
domain in `src/Bootstrap/` (Identity, Token, Session, Http, Mfa,
Organization). Routes come from `Bootstrap\Routes::table()`, entities from
`src/Entity`, migrations from `database/migrations` (18, driver-portable).

## 2. Secrets and environment (required at boot)

| Variable | Purpose |
| --- | --- |
| `APP_KEY` | HKDF seed for all peppers and the MFA-secret encrypter. **Minimum 32 bytes**; boot fails otherwise. Rotating it invalidates every stored hash: see `docs/auth/key-rotation.md`. |
| `AUTH_JWT_PRIVATE_KEY` / `AUTH_JWT_PUBLIC_KEY` | RSA keypair (PEM) signing/verifying access tokens. |
| `AUTH_JWT_KID` | Optional; defaults to the full SHA-256 fingerprint of the public key. |
| `AUTH_JWT_PREVIOUS_PUBLIC_KEY` / `AUTH_JWT_PREVIOUS_KID` | Only during key rotation; keeps the retiring key in the JWKS for one access-TTL window. |
| `AUTH_ISSUER` / `AUTH_AUDIENCE` | Token `iss`/`aud`. |
| `AUTH_ACCESS_TOKEN_DENYLIST` | `1/true/on` enables instant access-token revocation (one cache read per request). |
| `AUTH_PASSWORD_BREACH_CHECK` | `1/true/on` enables the HIBP k-anonymity breach check on new passwords. |

Host config namespaces (all optional, documented defaults):
`auth.*` (token TTLs, refresh rotation/sliding, lockout, password policy, OTP,
step-up max age) and `auth.rate_limits.*` (per-group `limit`/`window`
overrides). Full tables: `docs/auth/configuration.md`.

Ports the host should bind for production: `SmsSenderInterface` and
`OtpMailerInterface` (defaults are log-only drivers that send nothing, loudly),
and a shared PSR-16 `CacheInterface` (defaults to in-process memory, which
cannot hold rate limits across workers).

## 3. Token model

- **Access token** (JWT, short TTL): claims `sub`, `jti`, `sid`, `org`,
  `roles`, `scope`, `email_verified`, `mfa`, `amr`, `auth_time`.
- **Refresh token** (opaque, stored hashed): rotates on every use within a
  family; `sid` = family = session. Replaying a rotated token revokes the
  whole family (theft detection).
- `mfa`/`amr`/`auth_time` describe how the user authenticated. They are
  persisted on the session row, so they survive refresh and switch-org;
  step-up re-stamps `auth_time`.
- **mfa_token ticket**: login returns it instead of a session when the user
  has a confirmed factor (`purpose=login_mfa`, short TTL). Only
  `/auth/mfa/challenge` and `/auth/mfa/verify` accept it.
- **Never trust token claims for authorization.** Polaris re-resolves
  roles/permissions from the database on every permission check; `roles` and
  `scope` claims are hints for UIs.
- **Step-up**: sensitive routes require `now - auth_time <= step_up.max_age`
  for users with a confirmed factor. A stale `auth_time` gets
  `401 step_up_required`; clear it via `POST /auth/mfa/step-up`. Gated routes:
  `POST /auth/password/change`, `POST /auth/mfa/recovery-codes/regenerate`,
  `DELETE /auth/mfa/factors/{id}`, `DELETE /orgs/{id}`,
  `POST /users/{id}/disable`, `DELETE /users/{id}`.
- **Switch-org**: a session has one active org (`org` claim).
  `POST /auth/switch-org` re-points the session and mints a token with that
  org's `roles`/`scope`. All `/orgs/{id}...` calls must use the active org.

## 4. Route table (53 endpoints)

Full contracts (request fields, every status code, envelopes):
`docs/auth/api-reference.md`. Envelope conventions: success `{"data": ...}`,
validation `422 {"errors":[...]}`, semantic failures
`{"error":"<code>","message":"..."}`.

- **Identity/session**: `POST /auth/register|login|token/refresh|logout|logout-all|switch-org`,
  `POST /auth/email/verify[/resend]`, `POST /auth/password/forgot|reset|change`,
  `GET /auth/me|sessions`, `DELETE /auth/sessions/{id}`,
  `GET /auth/.well-known/jwks.json`.
- **MFA**: `POST /auth/mfa/{totp|sms|email}/enroll`,
  `POST /auth/mfa/{totp|sms|email}/confirm`, gate `POST /auth/mfa/challenge|verify`
  (mfa_token), `POST /auth/mfa/step-up[/challenge]`,
  `POST /auth/mfa/recovery-codes/regenerate`, `GET|PATCH|DELETE /auth/mfa/factors[/{id}]`.
- **Orgs/RBAC**: `POST|GET /orgs`, `GET|PATCH|DELETE /orgs/{id}`,
  `GET /orgs/{id}/members`, `PATCH /orgs/{id}/members/{userId}[/roles]`,
  `DELETE /orgs/{id}/members/{userId}`, `POST|GET /orgs/{id}/invites`,
  `DELETE /orgs/{id}/invites/{inviteId}`, `POST /auth/invites/accept`,
  `GET|POST /orgs/{id}/roles`, `PATCH|DELETE /orgs/{id}/roles/{roleId}`,
  `GET /permissions`.
- **User admin**: `GET|PATCH|DELETE /users/{id}`, `POST /users/{id}/disable|enable`.

## 5. Permission catalog and roles

Keys (org-scoped unless noted): `org.read`, `org.update`, `org.delete`,
`members.read`, `members.invite`, `members.update`, `members.remove`,
`roles.read`, `roles.manage`, `audit.read`, plus admin-scoped `users.read` and
`users.manage` (superadmin only). Templates cloned into every org: **owner**
(all org keys), **admin** (all except `org.delete`), **member** (`org.read`,
`members.read`, `roles.read`). **superadmin** is a global system role
resolving to the full catalog in any org. Domains declare
`REQUIRES_PERMISSIONS`; the AuthorizationMiddleware enforces them from the
database.

## 6. Multi-tenant invariants (the rules the permission check cannot express)

1. **No escalation**: an actor can only grant roles or permission keys they
   themselves hold (database-resolved). Applies to member role changes, role
   create/update, and invitations. Superadmin is exempt.
2. **Owners are protected**: only an owner or superadmin may modify, suspend,
   or remove an owner.
3. **Last-owner protection**: an org always keeps at least one active owner;
   the last one cannot be demoted, suspended, or removed by anyone (`409`).
4. **Cross-tenant isolation**: the path org must be the token's active org
   (superadmin exempt); everything else reads as `403`/`404`.
5. **PII gating**: invited/suspended members' emails are visible only with
   `members.invite`.
6. **Immutable anchors**: role slugs are immutable; the cloned `owner` role
   cannot be edited; `owner`/`admin`/`member` templates cannot be deleted;
   `superadmin` is unreachable through org paths.
7. **Suspension cuts access now**: suspending a member (or disabling a user)
   revokes the relevant sessions immediately, not at next token expiry.

## 7. Integration flows (agent recipes)

- **Login with MFA**: `POST /auth/login`; if the response has
  `mfa_required: true`, hold the `mfa_token`, optionally
  `POST /auth/mfa/challenge` (sms/email), then `POST /auth/mfa/verify` with
  the code (or a recovery code) to receive the real token pair.
- **Stay logged in**: `POST /auth/token/refresh` with the stored refresh
  token; persist the **new** refresh token every time. A `401 invalid_grant`
  means the session is gone; re-login.
- **Act inside an org**: `POST /auth/switch-org` first, then call
  `/orgs/{thatOrgId}/...` with the returned token.
- **Hitting `401 step_up_required`**: `POST /auth/mfa/step-up/challenge` (if
  sms/email), `POST /auth/mfa/step-up` with the code, retry the original
  request with the returned access token.
- **Observe**: subscribe PSR-14 listeners for the `Univeros\Polaris\Event\*`
  classes (catalog: `docs/auth/events.md`); the shipped `AuditLogListener`
  writes the append-only `auth_audit_log`, `MetricsListener` counts
  `polaris.auth.events`.

## 8. Operating and verifying

```bash
composer qa        # phpcs (PSR-12) + phpstan (level 5) + phpunit
vendor/bin/phpunit # DB-backed tests need DB_CONNECTION/DB_DATABASE/... (Postgres in CI); they skip without it
```

- Migrations run through the framework migrator; `PruneExpiredService` is the
  scheduled cleanup for expired transient rows (host wires it to cron).
- Key rotation runbook: `docs/auth/key-rotation.md`. Security model and
  threat table: `docs/auth/security.md`. Data model: `docs/auth/data-model.md`.
- When extending the module, add container wiring in the matching
  `src/Bootstrap/*Bindings.php` class, not in `Module.php`.
