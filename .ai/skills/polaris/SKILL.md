---
name: polaris
description: Integrate and operate univeros/polaris 2.x, the Univeros module for Polaris for PHP (polaris/core): authentication, MFA/OTP, sessions, multi-tenant organizations and RBAC. Use when registering the module in a Univeros host, configuring its environment and ports, wiring bin/altair and the migration, protecting the application's own routes with Polaris access tokens, calling the HTTP API, or reasoning about the token model and the tenant invariants.
---

# Polaris: auth, MFA, and multi-tenant RBAC on Univeros

`univeros/polaris` 2.x is a Univeros module around Polaris for PHP. The
behaviour (identity, MFA, sessions, organizations, RBAC, the 52 endpoints, the
schema) is `polaris/core` under the `Polaris\` namespaces; this package is the
glue: `Univeros\Polaris\Module` builds Polaris from the host's environment and
container, `PolarisMiddleware` serves the Polaris routes, `TokenFactoryBridge`
lets the framework's `TokenAuthenticationMiddleware` accept Polaris tokens,
one Cycle migration installs the schema, `Console\Commands` adds the
`polaris:*` commands. The HTTP contract is the 1.x one (sections 3 to 7 below
are unchanged); `docs/auth/` is the design, `docs/auth/api-reference.md` the
endpoint catalog.

## 1. Registration

```php
// config/modules.php in the host
return [
    new Univeros\Polaris\Module(),
];
```

`Module::apply()` binds lazy factories only: `Polaris\Polaris`, `Graph`,
`Router`, `Pipeline`, `PolarisMiddleware` and the framework's token contracts.
Nothing is built until the first request or command resolves it, so
`bin/altair db:migrate` runs before the keys exist; `bin/altair polaris:doctor`
is the boot check. `middleware()` puts `PolarisMiddleware` at
`MiddlewarePriority::EXCEPTION_HANDLER - 100` (outside the exception handler,
which would rewrite Polaris's 4xx envelopes into problem+json); the Polaris
routes are not in the FastRoute table (`bin/altair polaris:manifest` lists
them); `migrationDirectories()` points at the module's one migration.

The application ships its own `bin/altair` (the framework's `vendor/bin/altair`
boots without the application's container): build `config/container.php`,
apply `CliConfiguration` over the framework's `src/Altair/*/Cli` directories,
`add()` each of `Univeros\Polaris\Console\Commands::all($container)`, run.
`examples/univeros/bin/altair` is the file.

## 2. Environment and ports

Read through the framework's `Env` (`$_ENV`, `$_SERVER`, then `getenv()`; a
`.env` loaded by `EnvironmentConfiguration` counts):

| Variable | Purpose |
| --- | --- |
| `APP_KEY` | At least 32 bytes; every pepper and the MFA-secret encrypter derive from it. |
| `AUTH_JWT_PRIVATE_KEY` / `AUTH_JWT_PUBLIC_KEY` | RS256 key pair (PEM) signing and verifying access tokens. |
| `AUTH_JWT_KID`, `AUTH_JWT_PREVIOUS_PUBLIC_KEY`, `AUTH_JWT_PREVIOUS_KID` | Optional key id; the retiring key during rotation (`docs/auth/key-rotation.md`). |
| `AUTH_ISSUER` / `AUTH_AUDIENCE` | Token `iss` (default `polaris`) and `aud` (none). |
| `AUTH_ACCESS_TOKEN_DENYLIST`, `AUTH_PASSWORD_BREACH_CHECK` | `1`/`true`/`on` enables instant revocation, the HIBP breach check. |
| `DB_CONNECTION`, `DB_DATABASE`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` | The database as `CycleOrmConfiguration` reads it (`postgres`, `mysql`, `sqlite`); Polaris opens its own connection on the same settings. |
| `POLARIS_DSN`, `POLARIS_DB_USER`, `POLARIS_DB_PASSWORD` | The database of an application without an ORM. |
| `POLARIS_PATH_PREFIX` | Mounts the Polaris routes under a prefix (`/`). |

Every port takes the container's binding when registered before Polaris
resolves, else core's default: `Polaris\Config\Secrets` and `AuthConfig`
(over the environment), `Polaris\Contract\DatabaseAdapter` or `PDO` (over
`DatabaseSettings` and the environment), `OtpMailerInterface` and
`SmsSenderInterface` (defaults log and send nothing), PSR-16 `CacheInterface`
(rate limits, the denylist and OTP send caps live there; bind one that outlives
a request in production), PSR-3 `LoggerInterface`, PSR-14
`EventDispatcherInterface` (without one the module dispatches to
`Polaris::listeners()` itself; with one, subscribe those listeners), `ClockInterface`,
`RateLimitConfig`, `RateStore`, `EncrypterInterface`, `MetricsInterface`,
`TotpProviderInterface`, `QrCodeRendererInterface`, `ResponseFactoryInterface`.

## 2a. Protecting the application's own routes

The module binds `TokenFactoryInterface` to `Token\TokenFactoryBridge` (Polaris
exceptions rethrown as the framework's, so the middleware answers 401),
`TokenExtractorInterface` to `Authorization: Bearer`,
`CredentialsExtractorInterface` and `IdentityValidatorInterface` to null
implementations (login is the only credential entry point), and
`TokenAuthenticationMiddleware` with `['ssl' => false, 'onError' => new
UnauthorizedResponder()]`. Scope it to your paths and place it after the
dispatcher:

```php
$container->singleton(AppAuthentication::class, static fn(Container $c) => new AppAuthentication(
    $c->make(TokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]]),
));
// middleware(): [['middleware' => AppAuthentication::class, 'priority' => MiddlewarePriority::DISPATCHER + 5]]
```

The action reads `TokenInterface::TOKEN_KEY` from the request attributes (in
the domain's `InputCollection` through `InputParser`): a `Token\DualToken`
whose `getMetadata('sub' | 'org' | 'roles' | 'mfa' | ...)` are the claims.
`examples/univeros/app/Account/Me.php` is the reference.

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

## 4. Route table (52 endpoints)

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
- **Observe**: subscribe PSR-14 listeners for the `Polaris\Event\*`
  classes (catalog: `docs/auth/events.md`); the shipped `AuditLogListener`
  writes the append-only `auth_audit_log`, `MetricsListener` counts
  `polaris.auth.events`.

## 8. Operating and verifying

```bash
composer qa        # phpcs (PSR-12) + phpstan (level 5) + phpunit + the contract replay (test:contract)
vendor/bin/phpunit # SQLite in memory without DB_CONNECTION; the DB_* variables select PostgreSQL (CI)
```

- `bin/altair db:migrate` installs the schema (the module's one Cycle
  migration); `Graph::prune()` (`Polaris\Maintenance\PruneExpiredService`) is
  the scheduled cleanup for expired transient rows (the host wires it to cron).
- Key rotation runbook: `docs/auth/key-rotation.md`. Security model and
  threat table: `docs/auth/security.md`. Data model: `docs/auth/data-model.md`.
- Behaviour changes belong to `polaris/core`; this module only wires. Its
  decisions are logged in `docs/decisions.md`; `composer test:contract` replays
  the 184 recorded 1.0 sequences through the module's Relay pipeline.
