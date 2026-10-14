# Changelog

All notable changes to `univeros/polaris` are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `Univeros\Polaris\Messaging\BusOutbox`: polaris/messaging's outbox on the Univeros Messaging bus. Passed as
  `MessagingPlugin`'s `outbox` and routed to a transport, a send leaves the request as a `SendMessage`
  (`Receipt::queued()`, counted once by the policy) and the worker delivers it through the channels and the
  fallback; the module registers the handler when univeros/messaging is configured. (#165)

### Changed
- `polaris/*` move to `^0.11` (Polaris for PHP 0.11). The module implements no messaging `Outbox`, so its
  breaking change does not reach the module; the contract and plugin suites replay unchanged.
- `polaris:schema:install-plugins` creates the missing tables with polaris/pdo's
  `SchemaInstaller::createMissing()` (and `--sql` prints them in `SqlSchema::ordered()`), instead of the
  foreign-key ordering the module kept of its own. Same output and behaviour. (#111)

## [2.3.0] - 2026-10-13

Univeros-native extras on univeros/framework 2.6: the Polaris section in the host's AgentSpec manifests, and
audit drains verified with the framework's `WebhookVerifyMiddleware`. With this release the module supports
every package of Polaris for PHP 0.10.

### Added
- The module contributes its section to Univeros AgentSpec (`ManifestContributorInterface`, univeros/framework
  2.6): `bin/altair manifest:generate` writes `.agent/modules/univeros/polaris.md` with every route of core
  and the configured plugins (auth, step-up, required permissions, error codes) and the permission catalog,
  byte-stable for `--check`. (#137)

### Changed
- Requires univeros/* `^2.6`.

### Documentation
- README: receiving `polaris/audit` drains with Univeros `WebhookVerifyMiddleware` (`sha256=` signatures,
  no timestamp header), now that the framework's signers accept the prefix (#124).

## [2.2.0] - 2026-10-12

Every `polaris/*` plugin of Polaris for PHP 0.10 is supported and tested through the module, plus the
Univeros-native pieces around them: plugin credentials on the host's own routes, the agents middleware,
the Doctor checks, `routes:list`, Observability metrics and testing helpers. Nothing changes for an
application that configures no plugin.

### Added
- With `univeros/introspection`, `bin/altair routes:list` (and `routes:show`) list the Polaris
  routes, core's and the plugins', beside the host's, with their endpoint classes. The dispatch
  table stays without them.
- With Univeros Observability's `Meter` bound and no `MetricsInterface` of the host's, Polaris
  counts its domain events (sign-ins, MFA, the plugins') through the Meter (`MeterMetrics`).
- `Univeros\Polaris\Testing\PolarisTesting` for the host's tests (with `polaris/testing`):
  `bind()` gives the container an in-memory database, fresh RS256 keys, an APP_KEY and an
  issuer; `token()` mints an access token for a user (organization, roles, MFA, delegated
  permissions) to call protected routes.
- The Univeros demo runs the audit, admin, API-keys, OAuth-provider and MCP plugins; its
  walkthrough adds an API key on the application's `/app/me` and an MCP `tools/list` with a token
  exchanged for the MCP resource (19 steps).
- Under `POLARIS_PATH_PREFIX`, the root `.well-known` forms of RFC 8414 and RFC 9728
  (`/.well-known/oauth-authorization-server/auth`,
  `/.well-known/oauth-protected-resource/auth/mcp`) reach the metadata Polaris serves under the
  prefix, when that is a Polaris route; any other `.well-known` path stays the host's.
- `bin/altair doctor` (with `univeros/doctor`) gains three checks: `polaris` (secrets, keys,
  auth settings, database, manifest), `polaris_plugins` (the plugins build; each plugin's
  `baseUrl` is mounted at `POLARIS_PATH_PREFIX`) and `polaris_schema` (the database matches the
  schema, the plugins' tables included), each with its fix.
- With `polaris/agents`, `AgentRequestMiddleware` is bound for the host's routes: a request to a
  capability's `location` must come from an agent with a live grant; other URLs pass through.
  README: the approval page and the agent SDKs.
- Every `polaris/*` plugin of Polaris for PHP 0.10 is supported: passkey, username,
  passwordless, social, anonymous, multi-session, audit, admin, messaging, sentinel, sso,
  scim, api-keys, oauth-provider, mcp and agents. Each plugin's own functional suite and
  recorded fixtures replay through the module in `composer test:plugins` (55 tests); no module
  code change was needed. The README has a recipe per plugin and the registration order.
- `PluginTokenAuthenticationMiddleware` (opt-in): the framework's token authentication plus the
  plugins' credentials (API keys, OAuth access tokens) on the host's own routes, resolved with
  the request by the plugins' bearer resolvers, the resolving plugin's middleware around the
  route (a key's own rate limit). Such tokens are delegated; the module binds
  `Polaris\Authorization\Gate`, which applies the restriction, for the host's authorization.

## [2.1.0] - 2026-10-12

The plugin foundation: any `polaris/*` plugin of Polaris for PHP 0.10 runs in a Univeros
application by configuration (`Univeros\Polaris\Plugins` or `POLARIS_PLUGINS`), with its tables,
commands and contract fixtures. With no plugin configured the HTTP contract and the schema are
unchanged; see UPGRADE.md for the one listener change.

### Added
- The configured plugins' console commands join `bin/altair` as `polaris:*`
  (`polaris:audit:prune`, `polaris:mcp`, ...), and `polaris:manifest`, `schema:export`,
  `schema:create` and `doctor` include the plugins (the module points their `--bootstrap` at
  the application's Polaris). With plugins configured `bin/altair` needs the secrets.
- `polaris:schema:install-plugins`: creates the tables the database lacks (the configured
  plugins' included) in foreign-key order and seeds the plugins' permissions; idempotent.
  `--sql` prints the statements for a host's own migration. `polaris:schema:create`,
  `schema:diff` and `schema:drop` include the configured plugins' tables. The install
  migration stays core-only: Cycle builds it without the container.
- Plugins: the polaris plugins an application runs are a bound `Univeros\Polaris\Plugins`
  (`new Plugins(new PasskeyPlugin(...))` in `config/container.php`), else the comma-separated
  class names in `POLARIS_PLUGINS`, built through the container. Their routes, tables,
  services, middleware and permissions join the module's. An entry that is not a plugin class
  fails boot naming it. With neither, nothing changes.
- `composer test:plugins` (part of `qa` and CI) replays each supported plugin's own functional
  suite and recorded fixtures through the module, as `test:contract` does for core's. First
  plugin: `polaris/username`.

### Changed
- With a bound PSR-14 dispatcher the Polaris listeners (the audit log, notifications, metrics,
  and every plugin's) no longer depend on the host subscribing them: the module runs them,
  then hands the event to the host's dispatcher. `POLARIS_LISTENERS=host` keeps 2.0's
  behaviour; see UPGRADE.md.
- `polaris/core`, `polaris/pdo`, `polaris/psr15`, `polaris/cli` and `polaris/testing` move to
  `^0.10`. No behaviour change: core's 52 routes and the 184 contract fixtures are unchanged
  from 0.1 and replay green through the module.

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

[2.3.0]: https://github.com/univeros/polaris/releases/tag/v2.3.0
[2.2.0]: https://github.com/univeros/polaris/releases/tag/v2.2.0
[2.1.0]: https://github.com/univeros/polaris/releases/tag/v2.1.0
[2.0.0]: https://github.com/univeros/polaris/releases/tag/v2.0.0
[1.0.0]: https://github.com/univeros/polaris/releases/tag/v1.0.0
