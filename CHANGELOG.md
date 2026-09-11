# Changelog

All notable changes to `univeros/polaris` are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-09-11

`univeros/polaris` 2.0 is a new major built on Polaris for PHP: `polaris/core` carries the
identity, MFA/OTP, session, organization and RBAC services, the 52 endpoints and the
schema, all contract-frozen against 1.0 (184 recorded request/response sequences replay
through this module's Relay pipeline in CI); this package is the Univeros module around
it. The HTTP contract of 1.0 is unchanged (`docs/auth/api-reference.md` in polaris-core),
with one documented exception: a request body field named like a request attribute no
longer overrides the attribute.

### Changed
- The module builds Polaris from the environment (`APP_KEY`, `AUTH_JWT_*`, `AUTH_ISSUER`,
  `AUTH_AUDIENCE`) on the application's database settings (`DB_*`, or `POLARIS_DSN` without
  an ORM) through `polaris/pdo`; the framework's cache, logger and event dispatcher are used
  when bound.
- Routes: `PolarisMiddleware`, contributed through `MiddlewareProviderInterface` ahead of the
  framework's exception handler, serves every Polaris path; the routes are no longer in the
  FastRoute table (`bin/altair polaris:manifest` lists them). `POLARIS_PATH_PREFIX` mounts
  them under a prefix.
- Migrations: one Cycle migration installs the schema and seeds the permission catalog through
  `Polaris\Pdo\SchemaInstaller`; the 18 migrations of 1.x are gone. `bin/altair db:migrate`
  on a fresh database installs Polaris.
- The framework's `TokenAuthenticationMiddleware` keeps working with Polaris access tokens
  through `TokenFactoryBridge`; the application scopes it to its protected paths with
  `$container->make(TokenAuthenticationMiddleware::class, ['rules' => [...]])`.
- Console: `polaris:schema:export`, `polaris:schema:create`, `polaris:schema:drop`,
  `polaris:schema:diff`, `polaris:manifest`, `polaris:doctor` from `polaris/cli`, added by the
  application's own `bin/altair` through `Univeros\Polaris\Console\Commands::all()`.
- The default token issuer without `AUTH_ISSUER` is `polaris` (1.x minted `univeros/polaris`).

### Removed
- Every class under `Univeros\Polaris\` except the module glue; use the `Polaris\` namespaces
  of `polaris/core`. Cycle entities and repositories: Polaris no longer maps entities into the
  application's ORM schema.
- The AES-CBC encrypter of 1.x. There is no compatibility path (see UPGRADE).

## [1.0.0] - 2026-06-11

First stable release: the authentication, MFA/OTP, and multi-tenant RBAC
module for the univeros framework. A host registers one `Module` class and
gets the full surface below as routes, entities, migrations, middleware, and
PSR-14 events. See `docs/auth/` for the specification and
`docs/auth/api-reference.md` for the implemented HTTP contracts (52
endpoints).

### Identity and sessions

- Registration with email verification (single-use hashed tokens,
  enumeration-safe responses) and resend.
- Password login with Argon2id hashing, transparent rehash, timing-equalized
  verification, sliding-window lockout, and optional verified-email and
  HIBP breach-check (k-anonymity) gates.
- JWT access tokens (RSA, JWKS endpoint, key-rotation overlap window) plus
  opaque rotating refresh tokens with family-based reuse detection: replaying
  a rotated token revokes the whole session family.
- Session management: device list, logout, logout-all, per-session revocation,
  and an optional instant access-token denylist.
- Password forgot/reset/change with logout-everywhere semantics; reset and
  verification tokens are stored only as keyed HMACs.

### MFA

- TOTP (RFC 6238, encrypted secrets, QR provisioning), SMS, and email factors
  with enrollment + confirmation flows; ten single-use recovery codes issued
  on the first confirmed factor.
- The login MFA gate: a short-lived single-purpose ticket bridges the password
  step to factor verification before any session is minted.
- Step-up re-authentication for sensitive operations, stamped via `auth_time`;
  `mfa`/`amr`/`auth_time` persist across refresh and org switching.
- OTP hygiene: codes stored as keyed HMACs, attempt budgets and consumption
  enforced by atomic conditional updates, send quotas and resend cooldowns
  against OTP bombing.

### Multi-tenant RBAC

- Organizations with soft delete, slug uniqueness, and per-org role templates
  (owner / admin / member) cloned from system templates; a global `superadmin`
  override for platform operators.
- Members: listing (with PII gating of invited/suspended emails), role
  assignment, suspension with immediate org-scoped session revocation, and
  removal.
- Single-use, expiring invitations bound to the invitee's email.
- Custom roles with a 12-key permission catalog; database-resolved
  authorization on every check (token claims are never trusted for authority).
- Tenant invariants enforced beyond the permission check: no privilege
  escalation, owners protected from non-owners, last-owner protection,
  cross-tenant isolation on every org route.
- User administration: read/update (self or admin), disable/enable, and
  anonymizing tombstone deletion.

### Hardening and operations

- Per-IP rate-limit budgets per endpoint group plus a global per-user budget
  across authenticated endpoints; user-agent sanitization at the edge.
- Two security audits (#44 sign-off and the #97 follow-ups) fully remediated:
  atomic rotation/OTP/recovery claims, APP_KEY minimum length, full-length
  key fingerprints, typed challenge purposes, abuse caps.
- Append-only audit log (actor, org, ip, user agent, whitelisted metadata),
  domain metrics counter, and notification listeners over a catalog of ~35
  PSR-14 events.
- 18 driver-portable migrations, scheduled pruning of expired transient rows,
  and a key-rotation runbook.
- Verified by 519 tests (unit, persistence against a real driver, and
  end-to-end functional tests over the real middleware pipeline), with phpcs
  (PSR-12) and phpstan level 5 clean.

### Documentation and agent experience

- Full specification under `docs/auth/` with the API reference and event
  catalog regenerated from the shipped code.
- One YAML spec per implemented endpoint under `api/`, verified 1:1 against
  the route table.
- An agent skill at `.ai/skills/polaris/SKILL.md` covering registration,
  configuration, the token model, the permission catalog, and the tenant
  invariants.

[2.0.0]: https://github.com/univeros/polaris/releases/tag/v2.0.0
[1.0.0]: https://github.com/univeros/polaris/releases/tag/v1.0.0
