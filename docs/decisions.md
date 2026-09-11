# Decisions: univeros/polaris 2.0

Append only, dated. The owner's decisions of 2026-09-10 (the new major on `polaris/core`, `polaris/psr15`,
`polaris/pdo` and `polaris/cli`; `PolarisMiddleware` ahead of the framework's exception handler; no
compatibility encrypter; one Cycle migration over `Polaris\Pdo\SchemaInstaller`; the HTTP contract frozen by
the 184 recorded fixtures) are recorded in `polaris-core`'s `docs/adapters/univeros-polaris-2.0.md`, the
hand-off this work applies. What follows is what was decided while applying it.

## Log

- 2026-09-11 · WP0 · `1.x` is a branch cut at `v1.0.0` (pushed before the first 2.0 change), so a 1.x fix has
  a home; `main` carries 2.0. Work packages are branches named `2.0/wpN` from a fresh `main`, one PR each,
  squash-merged with the subject `<type>: <description> (#N)`.
- 2026-09-11 · WP0 · `docs/auth/` stays as the design reference (the data model, the flows, the MFA and RBAC
  rules, the API reference and the security model are the ones `polaris/core` implements, contract-frozen);
  its README says that the implementation is `polaris/core` and that only the module glue lives here.
  · Rejected: deleting the directory (the design has no other home in this repository and the 2.0 README
  links to it); rewriting it against the `Polaris\` namespaces (the same text lives in `polaris-core`'s
  `docs/auth/`, maintained there).
- 2026-09-11 · WP0 · `BearerTokenExtractor`, `NullCredentialsExtractor` and `UnauthorizedResponder` stay in
  WP0, moved from `src/Http/Middleware/` to `src/Http/` with their tests, rather than deleted and re-added
  in WP1: they did not move into `polaris/core` (the hand-off lists them as kept from 1.0) and they depend
  on nothing that was deleted. `src/` is otherwise the placeholder module only.
- 2026-09-11 · WP0 · `composer qa` runs `cs`, `stan` and `test`; `test:contract` (the functional suite through
  the module's harness) is declared now and joins `qa` and CI in WP3, when `tests/Harness.php` exists.
  `composer test` already runs the `functional` suite through `polaris/core`'s default `PipelineHarness`,
  which proves in WP0 that the vendored suite (the `Polaris\Tests\` autoload-dev mapping, `polaris/testing`,
  `httpsoft/http-message`, the fixtures) runs from this repository. · Rejected: a `qa` that fails until WP3.
- 2026-09-11 · WP0 · `migrations/` exists from WP0 (a `.gitkeep`) so `phpstan.neon` and `phpcs.xml` can list
  `src`, `tests` and `migrations` before the migration lands in WP2.
- 2026-09-11 · WP0 · `.ai/skills/polaris/SKILL.md`, `README.md`, `CHANGELOG.md` and `AGENT.md` still describe
  1.x until WP4, the documentation work package; WP0 changes no prose except this file and the `docs/auth`
  note.
- 2026-09-11 · WP1 · Nothing is built in `Module::apply()`: every binding is a shared factory, so the one
  `Polaris` (and its PDO connection, manifest and JWT configuration) exists from the first request or
  command that resolves it. `bin/altair db:migrate` therefore boots on a host without `APP_KEY` or the JWT
  keys, and `polaris:doctor` is the boot check. · Rejected: building eagerly as 1.x did (fails every CLI
  command on a missing secret and opens a second database connection on every boot).
- 2026-09-11 · WP1 · The config assembly and the connection live in two small classes,
  `Bootstrap\PolarisConfig::fromContainer()` and `Database\Connection` (`fromEnvironment()`,
  `fromSettings()`, `fromDsn()`, `databaseEnvironment()`), not as `Module::pdo()` and
  `Module::databaseEnvironment()` static helpers as the hand-off sketched; the behaviour is the one
  described there and `Module` stays the binding list. The WP2 migration calls
  `Connection::fromEnvironment()`. `fromDsn()` delegates to `Polaris\Cli\Database::connect()` (exception
  mode, `PRAGMA foreign_keys = ON` on SQLite), which the `polaris:*` commands use too.
- 2026-09-11 · WP1 · Every `Polaris\Wiring\Config` port takes the container's binding when `has()` says one is
  registered (mailer, SMS, breach check, cache, clock, dispatcher, logger, rate limits, rate store,
  encrypter, metrics, TOTP, QR codes, response factory), else null for core's default; the database is a
  bound `DatabaseAdapter`, else a bound `PDO` wrapped in `PdoAdapter`, else a bound `DatabaseSettings`
  (what `CycleOrmConfiguration` registers), else the environment (`DB_*` first, then `POLARIS_DSN` with
  `POLARIS_DB_USER` and `POLARIS_DB_PASSWORD`); the `sqlserver` driver of `DatabaseSettings` is refused
  because `polaris/pdo` has no schema for it.
- 2026-09-11 · WP1 · The environment is read through the framework's `Altair\Configuration\Support\Env`
  (`$_ENV`, `$_SERVER`, then `getenv()`), resolved from the container (`Module::env()`):
  `EnvironmentConfiguration` binds `Env` and loads `.env` with `Dotenv::createImmutable()` when `Env` is
  resolved, filling `$_ENV` and `$_SERVER` but not `getenv()`, so a `new Env()` or
  `EnvironmentConfig::secrets()`'s `getenv()` default could read before the load or miss a `.env` key. The default issuer without
  `AUTH_ISSUER` is core's `polaris` (1.x minted `univeros/polaris`); no token outlives the upgrade, the
  UPGRADE text will say so.
- 2026-09-11 · WP1 · `ResponseFactoryInterface` is bound to `Laminas\Diactoros\ResponseFactory` when the host
  binds none (the skeleton binds none and builds its own), and `IdentityValidatorInterface` to a
  `NullIdentityValidator` that validates nothing: the framework's `TokenAuthenticationMiddleware` requires
  one, and with `NullCredentialsExtractor` it never sees credentials, so `POST /auth/login` stays the sole
  credential entry point. · Rejected: a validator over Polaris's password check (it would exist only to
  be bypassed).
- 2026-09-11 · WP1 · `TokenAuthenticationMiddleware` is bound as a shared autowired definition with the
  `options` parameter (`ssl => false`, `onError => UnauthorizedResponder`) so the host gets the unscoped
  middleware with `get()` and a scoped one with
  `$container->make(TokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule([...])]])`,
  the framework's own parameter mechanism. · Rejected: a `POLARIS_PROTECTED_PATHS` variable or a module
  setting (a second configuration surface for what the container already does).
- 2026-09-11 · WP1 · `PolarisMiddleware` serves only paths under `POLARIS_PATH_PREFIX`: `Polaris\Psr15\Router`
  strips the prefix when present and otherwise matches the bare path, so without the guard a host mounting
  Polaris under `/api` would have its own `/auth/...` routes captured. The guard is the module's, not a
  change to core (no entry in `behaviour-changes.md`; the endpoints' contract is untouched).
- 2026-09-11 · WP1 · The module's PSR-14 dispatcher (`Event\ListenerDispatcher`) resolves
  `Polaris::listeners()` from the container on the first dispatch (Polaris does not exist when its Config
  is assembled), sends every event to every listener (each Polaris listener ignores the events it does
  not handle) and honours `StoppableEventInterface`.
