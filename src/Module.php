<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Doctor\CheckRegistry;
use Altair\Http\Collection\RouteCollection;
use Altair\Introspection\Inspector\RouteInspector;
use Altair\Http\Contracts\CredentialsExtractorInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Messaging\Discovery\HandlerEntry;
use Altair\Messaging\Discovery\HandlerRegistry;
use Altair\Module\Contracts\ManifestContributorInterface;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\Migration\MigrationSource;
use Laminas\Diactoros\ResponseFactory;
use Override;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Http\AgentRequestMiddleware;
use Polaris\Authorization\Gate;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Loader;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Psr15\Router;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Univeros\Polaris\AgentSpec\ManifestSection;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Doctor\PluginsCheck;
use Univeros\Polaris\Doctor\PolarisCheck;
use Univeros\Polaris\Doctor\SchemaCheck;
use Univeros\Polaris\Http\BearerTokenExtractor;
use Univeros\Polaris\Http\NullCredentialsExtractor;
use Univeros\Polaris\Http\NullIdentityValidator;
use Univeros\Polaris\Http\PluginTokenAuthenticationMiddleware;
use Univeros\Polaris\Http\PolarisMiddleware;
use Univeros\Polaris\Http\UnauthorizedResponder;
use Univeros\Polaris\Messaging\SendMessage;
use Univeros\Polaris\Messaging\SendMessageHandler;
use Univeros\Polaris\Token\TokenFactoryBridge;

use function class_exists;
use function dirname;
use function rtrim;

/**
 * Polaris for PHP as a Univeros module: one line in `config/modules.php` and the host gets the
 * 52 Polaris endpoints, the framework's token authentication over Polaris access tokens, the
 * migration that installs the schema and the `polaris:*` console commands.
 *
 * `apply()` binds one {@see Polaris} built from the environment and what the container already
 * binds ({@see PolarisConfig}); nothing is built until the first request or command resolves it,
 * so `bin/altair db:migrate` runs without the JWT keys and `polaris:doctor` is the boot check.
 */
final class Module implements
    ModuleInterface,
    MiddlewareProviderInterface,
    MigrationDirectoriesProviderInterface,
    ManifestContributorInterface
{
    #[Override]
    public function name(): string
    {
        return 'univeros/polaris';
    }

    #[Override]
    public function apply(Container $container): void
    {
        $env = self::env($container);
        $prefix = PolarisConfig::pathPrefix($env);

        if (!$container->has(ResponseFactoryInterface::class)) {
            $container->singleton(ResponseFactoryInterface::class, static fn(): ResponseFactory => new ResponseFactory());
        }
        if (!$container->has(IdentityValidatorInterface::class)) {
            $container->singleton(IdentityValidatorInterface::class, NullIdentityValidator::class);
        }

        $container->singleton(
            Polaris::class,
            static fn(Container $c): Polaris => Polaris::create(PolarisConfig::fromContainer($c, $env)),
        );
        $container->singleton(Graph::class, static fn(Polaris $polaris): Graph => $polaris->graph());
        $container->singleton(Router::class, static fn(Graph $graph): Router => new Router($graph->manifest(), $prefix));
        $container->singleton(
            Pipeline::class,
            static fn(Graph $graph, ResponseFactoryInterface $responses): Pipeline => new Pipeline($graph, $responses, $prefix),
        );
        $container->singleton(PolarisMiddleware::class)->withParameters(['pathPrefix' => $prefix]);

        // The framework's token authentication over Polaris access tokens, for the host's own routes:
        // `Authorization: Bearer` only (no credential minting), every failure a 401 envelope, and
        // `ssl => false` because the host runs behind TLS termination. The host scopes it to its
        // protected paths with `$container->make(TokenAuthenticationMiddleware::class, ['rules' => [...]])`.
        $container->singleton(
            TokenFactoryInterface::class,
            static fn(Graph $graph): TokenFactoryBridge => new TokenFactoryBridge($graph->tokenFactory()),
        );
        $container->singleton(TokenExtractorInterface::class, static fn(): BearerTokenExtractor => new BearerTokenExtractor());
        $container->singleton(CredentialsExtractorInterface::class, NullCredentialsExtractor::class);
        $container->singleton(TokenAuthenticationMiddleware::class)
            ->withParameters(['options' => ['ssl' => false, 'onError' => new UnauthorizedResponder()]]);
        // Opt-in: the same, plus the plugins' credentials (API keys, OAuth tokens), for hosts that mount
        // it instead; such tokens are delegated, so the Gate is bound for the host's authorization.
        $container->singleton(PluginTokenAuthenticationMiddleware::class)
            ->withParameters(['options' => ['ssl' => false, 'onError' => new UnauthorizedResponder()]]);
        $container->singleton(Gate::class, static fn(Graph $graph): Gate => $graph->gate());

        // With univeros/doctor installed (its configuration applies before the modules), the Polaris
        // checks join `bin/altair doctor`.
        if ($container->has(CheckRegistry::class)) {
            $container->extend(CheckRegistry::class, static function (CheckRegistry $registry) use ($container, $env): CheckRegistry {
                $registry->add(new PolarisCheck($container, $env));
                $registry->add(new PluginsCheck($container, $env));
                $registry->add(new SchemaCheck($container, $env));

                return $registry;
            });
        }

        // With univeros/messaging configured (before the modules), the worker delivers the sends a
        // BusOutbox put on the bus.
        if ($container->has(HandlerRegistry::class)) {
            $container->extend(HandlerRegistry::class, static function (HandlerRegistry $registry): HandlerRegistry {
                $registry->register(new HandlerEntry(SendMessage::class, SendMessageHandler::class));

                return $registry;
            });
        }

        // With polaris/agents: its request middleware for the host's routes, matching request URLs against
        // the capabilities' locations (AgentsPlugin::of($graph)->requestMiddleware($graph, '<capability>')
        // binds one route to one capability).
        if (class_exists(AgentsPlugin::class)) {
            $container->singleton(
                AgentRequestMiddleware::class,
                static fn(Graph $graph): AgentRequestMiddleware => AgentsPlugin::of($graph)->requestMiddleware($graph),
            );
        }

        // With univeros/introspection installed, `bin/altair routes:list` shows the Polaris routes (core's
        // and the plugins') beside the host's; the dispatch table itself stays without them.
        if ($container->has(RouteInspector::class)) {
            $container->extend(
                RouteInspector::class,
                static fn(RouteInspector $inspector, Container $c): RouteInspector => new RouteInspector(self::routes($c, $env, $prefix)),
            );
        }
    }

    /**
     * A copy of the host's route table with every Polaris route (`METHOD PATH` => endpoint class) added.
     */
    private static function routes(Container $container, Env $env, string $prefix): RouteCollection
    {
        $hosts = $container->get(RouteCollection::class);
        \assert($hosts instanceof RouteCollection);
        $routes = new RouteCollection($hosts->toArray());
        foreach (self::endpoints($container, $env) as $spec) {
            $routes->put($spec->method . ' ' . rtrim($prefix, '/') . $spec->path, $spec->class);
        }

        return $routes;
    }

    /**
     * Core's endpoints and the configured plugins', read from their manifests without building Polaris
     * (no secrets or database needed).
     *
     * @return list<EndpointSpec>
     */
    private static function endpoints(Container $container, Env $env): array
    {
        $directories = [Loader::defaultDirectory()];
        foreach (PolarisConfig::plugins($container, $env) as $plugin) {
            $directory = $plugin::manifestDirectory();
            if ($directory !== null) {
                $directories[] = $directory;
            }
        }

        return (new Loader(...$directories))->load()->endpoints();
    }

    /**
     * The environment through the container: `EnvironmentConfiguration` loads `.env` when `Env` is
     * resolved, so resolving it here (rather than `new Env()`) makes a `.env` key visible to the
     * module; without that configuration the container builds a plain `Env`.
     */
    public static function env(Container $container): Env
    {
        $env = $container->get(Env::class);
        \assert($env instanceof Env);

        return $env;
    }

    /**
     * {@see PolarisMiddleware} ahead of the framework's exception handler, which would rewrite
     * every 4xx/5xx Polaris answers into problem+json; the Polaris routes are not in the
     * FastRoute table (`bin/altair polaris:manifest` lists them).
     *
     * @return list<array{middleware: class-string<PolarisMiddleware>, priority: int}>
     */
    #[Override]
    public function middleware(): array
    {
        return [
            ['middleware' => PolarisMiddleware::class, 'priority' => MiddlewarePriority::EXCEPTION_HANDLER - 100],
        ];
    }

    #[Override]
    public function manifestDescription(): string
    {
        return 'Polaris for PHP: authentication, MFA/OTP, organizations and RBAC; routes, auth and permissions.';
    }

    /**
     * The Polaris section of `bin/altair manifest:generate` (`.agent/modules/univeros/polaris.md`): core's
     * routes and the configured plugins', with their auth, permissions and errors.
     */
    #[Override]
    public function manifest(Container $container): string
    {
        $env = self::env($container);

        return ManifestSection::render(self::endpoints($container, $env), PolarisConfig::pathPrefix($env));
    }

    /**
     * @return list<MigrationSource>
     */
    #[Override]
    public function migrationDirectories(): array
    {
        return [new MigrationSource(dirname(__DIR__) . '/migrations', __NAMESPACE__ . '\\Migrations')];
    }
}
