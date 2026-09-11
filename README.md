# univeros/polaris

> **Polaris for PHP as a Univeros module.** One line in `config/modules.php` and a
> [Univeros](https://univeros.io) application gets authentication, MFA/OTP, sessions with rotating
> refresh tokens, multi-tenant organizations and RBAC: the 52 endpoints of
> [`polaris/core`](https://github.com/univeros/polaris-core), served by the framework's own pipeline.

![PHP](https://img.shields.io/badge/PHP-8.3%2B-777BB4?logo=php&logoColor=white)
![Univeros module](https://img.shields.io/badge/Univeros-module-1d76db)
![Polaris for PHP](https://img.shields.io/badge/polaris%2Fcore-0.1-0052cc)
![MFA](https://img.shields.io/badge/MFA-TOTP%20%C2%B7%20SMS%20%C2%B7%20email-d93f0b)

`univeros/polaris` 2.0 is the Univeros module built on Polaris for PHP: `polaris/core` carries the
identity, MFA/OTP, session, organization and RBAC services, the endpoints and the schema, framework-free
and contract-frozen; `polaris/psr15`, `polaris/pdo` and `polaris/cli` give it a PSR-15 pipeline, a PDO
adapter and a console. This package is the glue between them and a Univeros host: a module that builds
Polaris from the application's environment and container, a middleware that serves the Polaris routes, a
bridge that lets the framework's `TokenAuthenticationMiddleware` accept Polaris access tokens, one Cycle
migration and the `polaris:*` commands. The 1.x HTTP contract is unchanged: the 184 request/response
sequences recorded against 1.0 replay through this module's Relay pipeline in CI.

Upgrading from 1.x? Read [UPGRADE.md](UPGRADE.md) first: 2.0 is a new major, and TOTP factors are
re-enrolled.

## Install

```sh
composer require univeros/polaris:^2.0
```

```php
// config/modules.php
return [
    new Univeros\Polaris\Module(),
];
```

That is the whole registration. The module contributes its middleware and its migration through the
framework's `MiddlewareProviderInterface` and `MigrationDirectoriesProviderInterface`, so
`public/index.php` of the skeleton stays as `composer create-project univeros/univeros` wrote it.

## The environment

Polaris reads the same variables 1.x read, through the framework's `Env` (`$_ENV`, `$_SERVER`, then
`getenv()`, so a `.env` loaded by `EnvironmentConfiguration` counts):

| Variable | Purpose |
| --- | --- |
| `APP_KEY` | At least 32 bytes; the key every pepper and the MFA-secret encrypter derive from. |
| `AUTH_JWT_PRIVATE_KEY`, `AUTH_JWT_PUBLIC_KEY` | The RS256 key pair (PEM) that signs and verifies access tokens. |
| `AUTH_JWT_KID`, `AUTH_JWT_PREVIOUS_PUBLIC_KEY`, `AUTH_JWT_PREVIOUS_KID` | Optional: the key id and the retiring key during a rotation. |
| `AUTH_ISSUER`, `AUTH_AUDIENCE` | The `iss` and `aud` claims (`polaris` and none by default). |
| `AUTH_ACCESS_TOKEN_DENYLIST`, `AUTH_PASSWORD_BREACH_CHECK` | `1`, `true` or `on` enables instant revocation and the breached-password check. |
| `DB_CONNECTION`, `DB_DATABASE`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` | The database, as `CycleOrmConfiguration` reads it (`postgres`, `mysql`, `sqlite`). Polaris opens its own connection on the same settings. |
| `POLARIS_DSN`, `POLARIS_DB_USER`, `POLARIS_DB_PASSWORD` | The database of an application without an ORM. |
| `POLARIS_PATH_PREFIX` | Mounts the Polaris routes under a prefix (`/` by default). |

A `Polaris\Config\Secrets` or `Polaris\Config\AuthConfig` instance bound in the container before the
module resolves wins over the environment, and so does every other port: a `Polaris\Contract\DatabaseAdapter`
or a `PDO`, an `OtpMailerInterface` and an `SmsSenderInterface` (the defaults log and send nothing),
a PSR-16 `CacheInterface` (rate limits, the denylist and the OTP send caps live there, so a production
host binds one that outlives a request), a PSR-3 logger, a PSR-14 dispatcher, a clock, the rate limits,
the encrypter, the metrics sink, the TOTP provider and the QR renderer. Without a dispatcher the module
dispatches Polaris events to `Polaris::listeners()` itself (the audit log, notifications, metrics); with
one, subscribe those listeners to it.

Nothing is built at boot: the one `Polaris` (and its connection, manifest and JWT configuration) exists
from the first request or command that resolves it, so `bin/altair db:migrate` runs before the keys
exist and `bin/altair polaris:doctor` is the boot check.

## The routes

`Univeros\Polaris\Http\PolarisMiddleware` runs first in the pipeline, ahead of the framework's
`ExceptionHandlerMiddleware` (which would rewrite every 4xx/5xx Polaris answers into problem+json), and
serves every manifest path through `Polaris\Psr15\Pipeline`: the Polaris routes are not in the FastRoute
table, `bin/altair polaris:manifest` lists them (`--format=openapi` renders the OpenAPI document). Any
other path continues to the framework's dispatcher. A JSON body is decoded from the request bytes, since
`ServerRequestFactory::fromGlobals()` hands `$_POST` over as the parsed body.

The full catalog with request and response shapes is `docs/auth/api-reference.md` (the design lives in
[`docs/auth/`](docs/auth/); the implementation is `polaris/core`).

## Your own routes behind Polaris tokens

The module binds the framework's token contracts over Polaris: `TokenFactoryInterface` to a bridge over
Polaris's token factory (invalid and expired tokens become the framework's `InvalidTokenException`, so
the middleware answers 401), `TokenExtractorInterface` to `Authorization: Bearer`, and
`TokenAuthenticationMiddleware` with `['ssl' => false, 'onError' => new UnauthorizedResponder()]` (a 401
JSON envelope on every failure, plain http accepted behind TLS termination). Scope it to your protected
paths with the container's own parameter mechanism and put it after the dispatcher:

```php
// the application's module
public function apply(Container $container): void
{
    $container->singleton(AppAuthentication::class, static fn(Container $c): AppAuthentication => new AppAuthentication(
        $c->make(TokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]]),
    ));
}

public function middleware(): array
{
    return [['middleware' => AppAuthentication::class, 'priority' => MiddlewarePriority::DISPATCHER + 5]];
}
```

The action then reads the token from the request attribute `TokenInterface::TOKEN_KEY` (through the
framework's `InputParser`, it is in the domain's `InputCollection`): a `Univeros\Polaris\Token\DualToken`
that implements both the framework's and Polaris's token contract, with the claims (`sub`, `org`,
`roles`, `mfa`, ...) under `getMetadata()`. [`examples/univeros`](examples/univeros) does exactly this for
`GET /app/me`.

## The database and `bin/altair`

The module ships one Cycle migration (`migrations/20260910.000000_0_install_polaris.php`) that installs
the schema for the connection's dialect and seeds the permission catalog and the system roles through
`Polaris\Pdo\SchemaInstaller`, on the migrator's own connection inside its transaction. The framework's
`vendor/bin/altair` boots a bare container, so the application ships its own entry point that builds
`config/container.php` first and adds the Polaris commands:

```php
#!/usr/bin/env php
<?php
use Altair\Cli\Application;
use Altair\Cli\Configuration\CliConfiguration;
use Univeros\Polaris\Console\Commands;

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
chdir($root);
$container = require $root . '/config/container.php';           // configurations, then the modules
(new CliConfiguration(glob($root . '/vendor/univeros/framework/src/Altair/*/Cli') ?: []))->apply($container);
$application = $container->make(Application::class);
foreach (Commands::all($container) as $command) {
    $application->add($command);
}
exit($application->run());
```

```sh
bin/altair db:migrate            # installs Polaris on a fresh database
bin/altair polaris:schema:diff   # proves the database matches the schema
bin/altair polaris:doctor        # secrets, keys, auth settings, database, manifest
bin/altair polaris:manifest      # the 52 routes (--format=openapi for the document)
bin/altair polaris:schema:export --target=sql:postgres
bin/altair polaris:schema:create / polaris:schema:drop
```

## The demo

[`examples/univeros`](examples/univeros) is the `univeros/univeros` skeleton with the module registered:
`bin/setup` writes `.env` and an RS256 key pair, runs `db:migrate`, `polaris:schema:diff` and
`polaris:doctor`; `bin/walkthrough.sh` registers a user, verifies the email, logs in, enrols TOTP, logs
in through MFA, creates an organization and switches to it, then calls the application's own `/app/me`.
CI runs it on every push.

## Development

```sh
composer install
composer qa              # phpcs, phpstan, phpunit (module and functional suites), the contract replay
composer test:contract   # the 184 recorded 1.0 fixtures through this module's Relay pipeline
```

`composer test` runs the module suite and `polaris/core`'s functional suite through the bare PSR-15
pipeline; `test:contract` runs the same suite and the contract fixtures through `tests/Harness.php`, an
`Altair\Container\Container` with the module applied and the skeleton's Relay pipeline. Any difference
is a bug in the module, never in the fixtures. Decisions taken while building 2.0 are logged in
[`docs/decisions.md`](docs/decisions.md); the orientation for coding agents is [`AGENT.md`](AGENT.md).

## License

Proprietary. See `composer.json`.

Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
