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
- 2026-09-11 · WP2 · The migration runs `SchemaInstaller` on Cycle's own connection (the protected
  `Driver::getPDO()` through reflection), inside the transaction Cycle wraps around `up()` and `down()`,
  not on a second connection as the hand-off sketched. Reproduced on a SQLite file: with the framework's
  `queryCache`, `Migrator::run()`'s `isConfigured()` leaves the `hasTable` cursor open on Cycle's
  connection, a SHARED lock that blocks any other connection's commit (`database is locked` after the
  60 s busy timeout); on the same connection, `DROP TABLE` still fails with `database table is locked`
  while the migrator's state cursor is pending, so the migration calls Cycle's public
  `Driver::clearCache()` first, which finalises the cached statements. One connection also makes the
  install atomic with PostgreSQL's transactional DDL. · Rejected: WAL journal mode (the switch needs the
  same exclusive lock); `Driver::disconnect()` inside the transaction (Cycle then commits a transaction
  that no longer exists); a `DatabaseAdapter` over Cycle's `DatabaseInterface` (a second adapter to
  maintain for one seeder call).
- 2026-09-11 · WP2 · `Console\Commands::all(Container)` returns the six `polaris/cli` commands renamed
  `polaris:*` on the module's bindings: the connection callable is `Connection::fromContainer()` (a bound
  `PDO`, else the framework's `DatabaseSettings`, else the environment), the secrets and auth callables
  `PolarisConfig::secrets()` and `::auth()`, so `polaris:schema:create` and `polaris:doctor` run on a host
  before Polaris itself can be built (no JWT keys yet) and on the database the application configured.
  `univeros/cli` discovers `#[Command]` classes by directory and has no module hook, so the application's
  own `bin/altair` adds them (the demo in WP4 shows the file).
- 2026-09-11 · WP2 · The migration test runs on the `DB_*` database when the environment sets one
  (PostgreSQL in CI, the way `db:migrate` runs there) and on a SQLite file otherwise; it discovers the
  module's directory through the container tag as `ModuleMigrationDirectories` does, applies through
  Cycle's `Migrator`, proves parity with `SchemaDiff`, rolls back.
- 2026-09-11 · WP3 · `tests/Harness.php` implements `Polaris\Tests\Functional\Harness` as the hand-off
  describes: an `Altair\Container\Container` with the test's Config bound first (the database adapter, the
  secrets and auth settings, the cache as `Polaris\Support\InMemoryCache` when the test binds none, and
  every other non-null port), `POLARIS_PATH_PREFIX` from the Config's prefix, then
  `ModuleConfiguration([new Module()])`; the request serialised to JSON bytes with an empty parsed body
  (what `ServerRequestFactory::fromGlobals()` produces); the skeleton's Relay pipeline through
  `ModuleMiddleware::collect()` with `ExceptionHandlerMiddleware` (capturing, `ProblemDetailsErrorHandler`),
  a `DispatcherMiddleware` over an empty FastRoute table and `ActionMiddleware`, resolved by the framework's
  `ContainerResolver`; `transportHeaders()` empty because Relay adds nothing. The 184 fixtures and the
  coverage test passed unchanged on the first run (185 tests, SQLite), so no difference was found and
  nothing is added to `behaviour-changes.md`. `qa` now ends with `test:contract`, and CI runs it as its
  own step after `composer test`.
- 2026-09-11 · WP4 · `examples/univeros` is the `univeros/univeros` 2.5.1 skeleton (`composer create-project`,
  inspected in a scratch directory first) with `public/index.php` and `config/container.php` unchanged and
  the module required from this repository through a path repository (`"univeros/polaris": "@dev"`,
  `../..`, symlinked), so the demo and CI always run the checkout; the demo's `composer.lock` is not
  committed (it would pin a branch-specific dev reference of the module). The application's own
  `App\AppModule` binds the JSON-lines mailbox (`var/mail.log`) as Polaris's mailer and an
  `AppAuthentication` decorator built from `$container->make(TokenAuthenticationMiddleware::class,
  ['rules' => [new RequestPathRule(['path' => ['/app']])]])`, contributed at `DISPATCHER + 5`; `GET /app/me`
  reads the `DualToken` from the `InputCollection` (the framework's `InputParser` merges the request
  attributes) and answers with the user from `Graph::users()`. · Rejected: a subclass of
  `TokenAuthenticationMiddleware` repeating the module's options; a `POLARIS_PROTECTED_PATHS` variable.
- 2026-09-11 · WP4 · `bin/setup` writes `DB_DATABASE` as an absolute path into `.env`: PHP's built-in server
  runs with `public/` as its working directory, so the skeleton's relative `var/polaris.sqlite` resolved
  under `public/` and the first request failed with "unable to open database file". The RS256 keys go
  into `.env` as double-quoted multi-line values (phpdotenv reads them) and into `var/keys/` as PEM files;
  `.env` is loaded by the framework's `EnvironmentConfiguration` (listed first in
  `config/configurations.php`, only when the file exists so `bin/setup` can run before it does), and
  `CycleOrmConfiguration` shares the `DB_*` settings with Polaris. `bin/altair` builds
  `config/container.php`, applies `CliConfiguration` over the framework's `src/Altair/*/Cli` directories
  and adds `Commands::all()`; it `chdir()`s to the project root so `db:migrate` finds
  `database/migrations`.
- 2026-09-11 · WP4 · `bin/walkthrough.sh` is a copy of polaris-core's `examples/walkthrough.sh` plus two steps
  of this demo's own (`GET /app/me` without a token answers 401 from the framework's middleware, with the
  org-scoped token 200 with the organization id), so the demo proves the token bridge, not only the
  Polaris routes. The `demo` CI job installs the demo, runs `bin/setup` and the walkthrough on PHP 8.3.
- 2026-09-11 · WP4 · `phpcs.xml` also covers `examples/univeros/{app,config,public}` (the skeleton's
  `PingInput` braces reformatted with phpcbf); phpstan does not, because the demo's classes autoload
  through the demo's own vendor (`univeros/framework`), not this package's.
- 2026-09-11 · WP4 · Documentation: `README.md` rewritten for 2.0 (install, `config/modules.php`, the
  environment and the ports, the routes, the token bridge for the application's routes, `bin/altair` and
  the migration, the demo, development), `CHANGELOG.md` and `UPGRADE.md` with the hand-off's text (plus
  the default-issuer note of WP1 and the application's own `bin/altair`), `AGENT.md` and
  `.ai/skills/polaris/SKILL.md` for the 2.0 layout (the sections on the token model, the route table, the
  permission catalog, the tenant invariants and the integration flows kept, since the contract is
  unchanged). Every README ends with the 2am.tech line as in polaris-core.
- 2026-09-11 · WP4 · Release: `v2.0.0` is a GitHub release created at the merge commit of WP4 on `main`
  (`gh release create v2.0.0 --target <sha>`) with the CHANGELOG's 2.0.0 section as its notes; Packagist
  refreshes through its hook.
