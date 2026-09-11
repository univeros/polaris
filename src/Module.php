<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Http\Contracts\CredentialsExtractorInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\Migration\MigrationSource;
use Laminas\Diactoros\ResponseFactory;
use Override;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Psr15\Router;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Http\BearerTokenExtractor;
use Univeros\Polaris\Http\NullCredentialsExtractor;
use Univeros\Polaris\Http\NullIdentityValidator;
use Univeros\Polaris\Http\PolarisMiddleware;
use Univeros\Polaris\Http\UnauthorizedResponder;
use Univeros\Polaris\Token\TokenFactoryBridge;

use function dirname;

/**
 * Polaris for PHP as a Univeros module: one line in `config/modules.php` and the host gets the
 * 52 Polaris endpoints, the framework's token authentication over Polaris access tokens, the
 * migration that installs the schema and the `polaris:*` console commands.
 *
 * `apply()` binds one {@see Polaris} built from the environment and what the container already
 * binds ({@see PolarisConfig}); nothing is built until the first request or command resolves it,
 * so `bin/altair db:migrate` runs without the JWT keys and `polaris:doctor` is the boot check.
 */
final class Module implements ModuleInterface, MiddlewareProviderInterface, MigrationDirectoriesProviderInterface
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

    /**
     * @return list<MigrationSource>
     */
    #[Override]
    public function migrationDirectories(): array
    {
        return [new MigrationSource(dirname(__DIR__) . '/migrations', __NAMESPACE__ . '\\Migrations')];
    }
}
