# univeros/polaris

> **Polaris for PHP as a Univeros module.** One line in `config/modules.php` and a
> [Univeros](https://univeros.io) application gets authentication, MFA/OTP, sessions with rotating
> refresh tokens, multi-tenant organizations and RBAC: the 52 endpoints of
> [`polaris/core`](https://github.com/univeros/polaris-core), served by the framework's own pipeline.

![PHP](https://img.shields.io/badge/PHP-8.3%2B-777BB4?logo=php&logoColor=white)
![Univeros module](https://img.shields.io/badge/Univeros-module-1d76db)
![Polaris for PHP](https://img.shields.io/badge/polaris%2Fcore-0.10-0052cc)
![MFA](https://img.shields.io/badge/MFA-TOTP%20%C2%B7%20SMS%20%C2%B7%20email-d93f0b)

`univeros/polaris` 2.x is the Univeros module built on Polaris for PHP: `polaris/core` carries the
identity, MFA/OTP, session, organization and RBAC services, the endpoints and the schema, framework-free
and contract-frozen; `polaris/psr15`, `polaris/pdo` and `polaris/cli` give it a PSR-15 pipeline, a PDO
adapter and a console. This package is the glue between them and a Univeros host: a module that builds
Polaris from the application's environment and container, a middleware that serves the Polaris routes, a
bridge that lets the framework's `TokenAuthenticationMiddleware` accept Polaris access tokens, one Cycle
migration and the `polaris:*` commands. Since 2.1 it also runs the `polaris/*` plugins (passkeys, social
sign-in, API keys, an OAuth/OIDC provider, MCP, agents, audit and more) by configuration. The 1.x HTTP contract is unchanged: the 184 request/response
sequences recorded against 1.0 replay through this module's Relay pipeline in CI.

Upgrading from 1.x? Read [UPGRADE.md](UPGRADE.md) first: 2.0 is a new major, and TOTP factors are
re-enrolled.

## Install

```sh
composer require univeros/polaris:^2.1
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
| `POLARIS_PLUGINS` | Comma-separated plugin classes, built through the container, when no `Univeros\Polaris\Plugins` is bound (see Plugins). |
| `POLARIS_LISTENERS` | `module` (default): the module runs `Polaris::listeners()`, then your bound dispatcher. `host`: your bound dispatcher gets the events as is and subscribes the listeners itself (2.0's behaviour). |

A `Polaris\Config\Secrets` or `Polaris\Config\AuthConfig` instance bound in the container before the
module resolves wins over the environment, and so does every other port: a `Polaris\Contract\DatabaseAdapter`
or a `PDO`, an `OtpMailerInterface` and an `SmsSenderInterface` (the defaults log and send nothing),
a PSR-16 `CacheInterface` (rate limits, the denylist and the OTP send caps live there, so a production
host binds one that outlives a request), a PSR-3 logger, a PSR-14 dispatcher, a clock, the rate limits,
the encrypter, the metrics sink, the TOTP provider and the QR renderer. Polaris events go to
`Polaris::listeners()` (the audit log, notifications, metrics, and every plugin's) and then to your
PSR-14 dispatcher when you bind one, so your listeners see `UserRegistered` and the rest.

Nothing is built at boot: the one `Polaris` (and its connection, manifest and JWT configuration) exists
from the first request or command that resolves it, so `bin/altair db:migrate` runs before the keys
exist and `bin/altair polaris:doctor` is the boot check.

## Plugins

Every `polaris/*` plugin of Polaris for PHP runs through the module. Require the package, then bind the
plugins in `config/container.php` (the way for a plugin taking arguments, such as URLs or PSR-17/18
factories only your application has):

```php
use Polaris\Passkey\PasskeyPlugin;
use Univeros\Polaris\Plugins;

$container->instance(Plugins::class, new Plugins(
    new PasskeyPlugin(origins: ['https://app.example.com'], rpName: 'Example'),
));
```

or name plugins without arguments in the environment: `POLARIS_PLUGINS="Polaris\Audit\AuditPlugin"`. A bound
`Plugins` wins over the variable; an entry that is not a plugin class fails boot naming it. Their routes
are served under `POLARIS_PATH_PREFIX`, their middleware and listeners run, their permissions join the
catalog. Install their tables with `bin/altair polaris:schema:install-plugins` (see below); their console
commands appear as `polaris:*`. A plugin taking a `baseUrl` (oauth-provider, mcp, agents) wants the URL
Polaris is mounted at, prefix included.

Every plugin's own contract fixtures replay through the module in CI (`composer test:plugins`).

**Order matters**: list `AuditPlugin`, `AdminPlugin` and `MessagingPlugin` first, `SsoPlugin` before
`ScimPlugin`, and `OAuthPlugin` before `McpPlugin` and `AgentsPlugin`, as each plugin's class
documentation asks. `baseUrl` is always where Polaris is mounted, prefix included
(`https://app.example.com/auth` with `POLARIS_PATH_PREFIX=/auth`). PSR-17 factories:
`laminas/laminas-diactoros` comes with the module. A PSR-18 client is yours to choose.

| Plugin (`composer require ...`) | Construct | Routes, commands, notes |
| --- | --- | --- |
| `polaris/audit` | `new AuditPlugin(retention: [...], hashChain: true)`; drains need a PSR-18 client | `/audit/*`; `polaris:audit:prune`, `polaris:audit:verify` (schedule the prune) |
| `polaris/admin` | `new AdminPlugin()` | `/admin/*` operator API; `polaris:admin:grant`, `polaris:admin:key` create the first principals |
| `polaris/messaging` | `new MessagingPlugin(channels: [...])` | becomes core's mailer and SMS sender when you bind none; `polaris:messaging:send` |
| `polaris/passkey` | `new PasskeyPlugin(origins: [...], rpName: '...')`: exact origins (https, or `http://localhost` in development) | `/passkey/*`; every passkey is an MFA factor `passkey` at `/auth/mfa/verify` and `/auth/mfa/step-up`; `registerPasskey()`, `signInWithPasskey()` in `@polaris-auth/client` |
| `polaris/username` | `new UsernamePlugin()` | `POST /username/sign-in`, `PATCH /username` |
| `polaris/passwordless` | `new PasswordlessPlugin(baseUrl: ..., redirectUris: [...])`, after `MessagingPlugin` (or bind a mailer and SMS sender) | `/magic-link/*`, `/email-otp/*`, `/phone/*`, `/one-time-token/*` |
| `polaris/social` | `new SocialPlugin(baseUrl: ..., providers: ['google' => ['client_id' => ..., 'client_secret' => ...]], httpClient: ..., requestFactory: ..., streamFactory: ...)` | `/social/*`; register `<baseUrl>/social/{provider}/callback` with each provider |
| `polaris/anonymous` | `new AnonymousPlugin(onConvert: fn(string $guestId, string $userId) => ...)` | `/anonymous/*`; `polaris:anonymous:prune` (schedule it) |
| `polaris/multi-session` | `new MultiSessionPlugin()` | `/multi-session/*`; the `X-Polaris-Device` header and the `polaris_ms_device` cookie |
| `polaris/sentinel` | `new SentinelPlugin(mode: 'observe')`; bind a cache that outlives a request | judges sign-up, sign-in, reset and code sends; `/admin/sentinel/*`; `polaris:sentinel:lists` |
| `polaris/sso` | `new SsoPlugin(baseUrl: ..., httpClient: ..., requestFactory: ..., streamFactory: ...)` | `/sso/*`, `/orgs/{id}/sso`, `/admin/sso`; SAML and OIDC URLs derive from `baseUrl` |
| `polaris/scim` | `new ScimPlugin(baseUrl: ...)`, after `SsoPlugin` | `/scim/v2/{connectionId}`, `/orgs/{id}/scim`, `/admin/scim` |
| `polaris/api-keys` | `new ApiKeysPlugin()` | `/api-keys/*`; a key (`Bearer pk_...` or `x-api-key`) authenticates every Polaris route as its owner |
| `polaris/oauth-provider` | `new OAuthPlugin(baseUrl: ..., consentUrl: ..., deviceUrl: ...)`; `audiences: ['<baseUrl>/mcp']` with mcp | `/oauth2/*`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` (under a prefix also at the root, as RFC 8414 asks: `/.well-known/oauth-authorization-server/auth`), `/orgs/{id}/oauth/clients`, `/admin/oauth/clients`; its tokens authenticate every Polaris route within their scopes |
| `polaris/mcp` | `new McpPlugin(baseUrl: ..., requests: new ServerRequestFactory(), responses: new ResponseFactory(), streams: new StreamFactory())` (the `Laminas\Diactoros` factories) | `POST /mcp`, `/.well-known/oauth-protected-resource/mcp` (and the RFC 9728 root form `/.well-known/oauth-protected-resource/auth/mcp` under a prefix); `polaris:mcp` (stdio) |
| `polaris/agents` | `new AgentsPlugin(baseUrl: ..., capabilities: [...], approvalUrl: ...)`, after `OAuthPlugin` | `/agents/*`, `/admin/agents/*`, `/.well-known/agent-configuration`; every capability is an MCP tool with mcp |

API keys and OAuth tokens authenticate the Polaris routes; your own routes behind the framework's
`TokenAuthenticationMiddleware` accept Polaris sessions only, unless you mount `PluginTokenAuthenticationMiddleware` (below).

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

### API keys and OAuth tokens on your routes

`TokenAuthenticationMiddleware` accepts Polaris sessions only. To accept the plugins' credentials too
(a `polaris/api-keys` key as `Bearer pk_...` or `x-api-key`, a `polaris/oauth-provider` access token),
mount `Univeros\Polaris\Http\PluginTokenAuthenticationMiddleware` instead, scoped the same way:

```php
$c->make(PluginTokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]])
```

It asks the plugins' resolvers with the request first, then falls back to the framework's behaviour; a
refused key is the same 401 envelope. Such a token is **delegated**: it may use only the subset of its
owner's permissions listed under `getMetadata(Gate::DELEGATED)`, and only `Polaris\Authorization\Gate`
applies that restriction. Authorize these routes through the Gate the module binds
(`$gate->allows($token, 'invoices.read')`), never from the user id alone, or a key gets its owner's full
authority.

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

The migration installs core. The tables of the plugins you configure (and their permissions) come from
`polaris:schema:install-plugins`, which creates only the tables the database lacks and seeds the
permission catalog, so it is safe to re-run after enabling another plugin. With `--sql` it prints the
statements instead, to paste into a migration of your own. `polaris:schema:diff` checks the plugins'
tables too.

```sh
bin/altair polaris:schema:install-plugins         # after enabling a plugin
bin/altair polaris:schema:install-plugins --sql   # the statements, for your own migration
```

The commands of the plugins you configure join as `polaris:*` (`polaris:audit:prune`, `polaris:mcp`,
`polaris:admin:grant`, ...), and `polaris:manifest`, `polaris:schema:export`, `polaris:schema:create`
and `polaris:doctor` include the plugins' routes, tables and permissions. Either builds Polaris, so
once you configure plugins `bin/altair` needs the secrets (`bin/setup` writes them before
`db:migrate`). Without plugins nothing is built at boot.

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
