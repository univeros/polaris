# AGENT.md: univeros/polaris

Orientation for coding agents working in this repository. Read this before editing. The human-facing
README is `README.md`; the identity design is `docs/auth/`; the decisions taken while building 2.0 are
`docs/decisions.md` (append only, dated).

## What this repository is

`univeros/polaris` is the Univeros module for Polaris for PHP. Since 2.0 the implementation is
[`polaris/core`](https://github.com/univeros/polaris-core) (the `Polaris\` namespaces: identity, MFA/OTP,
sessions, organizations, RBAC, the 52 endpoints declared in its `api/**/*.yaml`, the schema), with
`polaris/psr15` (the PSR-15 pipeline), `polaris/pdo` (the PDO adapter and the schema tools) and
`polaris/cli` (the console commands). Everything here is the glue between those packages and a Univeros
host; `git show v1.0.0` or the `1.x` branch is the self-contained 1.x module.

## The rules

1. **The HTTP contract is frozen.** `composer test:contract` replays the 184 request/response sequences
   recorded against 1.0 through this module's Relay pipeline (`tests/Harness.php`). A difference is a bug
   here, never in the fixtures; `polaris-core`'s `docs/extraction/behaviour-changes.md` is the only
   register of deliberate changes and nothing is added to it from this repository.
2. **No Polaris logic here.** Behaviour belongs to `polaris/core`; this module builds Polaris from the
   host's environment and container and hands requests to it. If something is missing in core, it is a
   `polaris-core` change first.
3. **`composer qa` green before proposing a commit**: phpcs (PSR-12), phpstan level 5, phpunit (the
   `module` suite and `polaris/core`'s functional suite through the bare pipeline), then `test:contract`.
   Never weaken the level or skip a test to get green.
4. **Decisions are logged**, not assumed: `docs/decisions.md`, dated, with the reason and the rejected
   alternatives.
5. **Namespaces.** This package is `Univeros\Polaris\`. `Polaris\` is `polaris/core` and friends (never
   copied or aliased here); `Altair\` is the framework (`univeros/*` packages). Do not confuse the three.
6. `~/Projects/polaris-core` (when present) is read-only from here.

## Layout

```
src/Module.php                     ModuleInterface, MiddlewareProviderInterface, MigrationDirectoriesProviderInterface
src/Bootstrap/PolarisConfig.php    the Polaris Config from the container's bindings and the environment
src/Database/Connection.php        the PDO Polaris runs on: a bound PDO, DatabaseSettings (DB_*), or POLARIS_DSN
src/Event/ListenerDispatcher.php   the PSR-14 dispatcher bound when the host binds none
src/Http/PolarisMiddleware.php     the Polaris routes, ahead of the exception handler, outside FastRoute
src/Http/BearerTokenExtractor.php  `Authorization: Bearer` for the framework's TokenAuthenticationMiddleware
src/Http/NullCredentialsExtractor.php, NullIdentityValidator.php   no credential minting: login is the only entry
src/Http/UnauthorizedResponder.php every auth failure of the host's routes is a 401 envelope
src/Token/TokenFactoryBridge.php   the framework's TokenFactoryInterface over Graph::tokenFactory()
src/Token/DualToken.php            one token for both contracts
src/Console/Commands.php           the six polaris/cli commands as polaris:*, for the application's bin/altair
migrations/                        one Cycle migration: SchemaInstaller on the migrator's connection
tests/Harness.php                  the functional suite and the fixtures through Relay (POLARIS_HARNESS)
tests/                             the module suite (bindings, middleware, bridge, connection, migration, console)
examples/univeros/                 the demo: the skeleton with the module, bin/altair, bin/setup, the walkthrough
docs/auth/                         the design (implemented by polaris/core); docs/decisions.md the log
```

## How the module works

`Module::apply()` binds lazy factories only: `Polaris` (built by `PolarisConfig::fromContainer()`: every
`Polaris\Wiring\Config` port takes the container's binding when registered, else core's default; the
secrets and auth settings from bound `Secrets`/`AuthConfig` or the environment; the database from a
bound `DatabaseAdapter`, a bound `PDO`, the framework's `DatabaseSettings`, or `POLARIS_DSN`), `Graph`,
`Router`, `Pipeline`, `PolarisMiddleware`, and the framework's token contracts over Polaris. Nothing is
built until the first request or command resolves it. `middleware()` puts `PolarisMiddleware` at
`MiddlewarePriority::EXCEPTION_HANDLER - 100`; `migrationDirectories()` points at `migrations/`.

The environment is read through the framework's `Env` resolved from the container, so `.env` loaded by
`EnvironmentConfiguration` is visible. Tests that describe an environment bind
`tests/Support/ArrayEnv.php` instead of calling `putenv()`.

## Useful commands

```
composer qa
composer test
composer test:contract                 # POLARIS_HARNESS=Univeros\Polaris\Tests\Harness phpunit --testsuite functional
vendor/bin/phpunit --testsuite module
examples/univeros/bin/setup && examples/univeros/bin/walkthrough.sh
```

`composer stan` may need `PHP_INI_SCAN_DIR` pointing at an ini with `memory_limit=-1`. The database
suites run on SQLite in memory with `DB_CONNECTION` unset and on PostgreSQL with the `DB_*` variables
`CycleOrmConfiguration` reads (CI exports them).
