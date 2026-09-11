<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests;

use Altair\Container\Container;
use Altair\Http\Middleware\ActionMiddleware;
use Altair\Http\Middleware\DispatcherMiddleware;
use Altair\Http\Middleware\ExceptionHandlerMiddleware;
use Altair\Http\Resolver\ContainerResolver;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Http\Support\ModuleMiddleware;
use Altair\Http\Support\ProblemDetailsErrorHandler;
use Altair\Module\ModuleConfiguration;
use FastRoute\RouteCollector;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\MetricsInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RateStore;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Functional\Harness as HarnessContract;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Relay\Relay;
use Univeros\Polaris\Module;

use function FastRoute\simpleDispatcher;
use function is_array;
use function json_encode;
use function putenv;

use const JSON_THROW_ON_ERROR;

/**
 * The functional suite and the 184 contract fixtures through this module (`composer test:contract`,
 * `POLARIS_HARNESS=Univeros\Polaris\Tests\Harness`): an `Altair\Container\Container` with the test's
 * instances bound before the module applies, then the skeleton's Relay pipeline (`public/index.php`
 * of `univeros/univeros` 2.5.1) with an empty FastRoute table, so every request travels
 * `PolarisMiddleware`, the exception handler, the dispatcher and the action stage as in production.
 */
final class Harness implements HarnessContract
{
    private const array PORTS = [
        'mailer' => OtpMailerInterface::class,
        'sms' => SmsSenderInterface::class,
        'breachCheck' => BreachedPasswordCheckInterface::class,
        'clock' => ClockInterface::class,
        'dispatcher' => EventDispatcherInterface::class,
        'logger' => LoggerInterface::class,
        'rateLimits' => RateLimitConfig::class,
        'rateStore' => RateStore::class,
        'encrypter' => EncrypterInterface::class,
        'metrics' => MetricsInterface::class,
        'totp' => TotpProviderInterface::class,
        'qrCodes' => QrCodeRendererInterface::class,
        'responseFactory' => ResponseFactoryInterface::class,
    ];

    private function __construct(private readonly Container $container, private readonly Relay $relay)
    {
    }

    #[Override]
    public static function create(Config $config): static
    {
        $container = new Container();
        $container->instance(DatabaseAdapter::class, $config->database);
        $container->instance(Secrets::class, $config->secrets);
        $container->instance(AuthConfig::class, $config->auth);
        // A production host binds a cache that outlives a request; the test's own PSR-16 cache stands in.
        $container->instance(CacheInterface::class, $config->cache ?? new InMemoryCache());
        foreach (self::PORTS as $property => $id) {
            if ($config->{$property} !== null) {
                $container->instance($id, $config->{$property});
            }
        }
        putenv('POLARIS_PATH_PREFIX=' . $config->pathPrefix);
        (new ModuleConfiguration([new Module()]))->apply($container);

        $responses = new ResponseFactory();
        $dispatcher = simpleDispatcher(static function (RouteCollector $collector): void {
        });
        $pipeline = ModuleMiddleware::collect($container, [
            [
                'middleware' => new ExceptionHandlerMiddleware(responseFactory: $responses, handler: new ProblemDetailsErrorHandler(), capture: true),
                'priority' => MiddlewarePriority::EXCEPTION_HANDLER,
            ],
            ['middleware' => new DispatcherMiddleware($dispatcher), 'priority' => MiddlewarePriority::DISPATCHER],
            [
                'middleware' => new ActionMiddleware(static fn(string $class): object => $container->make($class), $responses),
                'priority' => MiddlewarePriority::ACTION,
            ],
        ]);

        return new self($container, new Relay($pipeline, new ContainerResolver($container)));
    }

    #[Override]
    public function graph(): Graph
    {
        $graph = $this->container->get(Graph::class);
        \assert($graph instanceof Graph);

        return $graph;
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->relay->handle(self::wire($request));
    }

    /**
     * Relay adds nothing to a response.
     */
    #[Override]
    public static function transportHeaders(): array
    {
        return [];
    }

    /**
     * The tests build requests with a parsed body and no bytes; a client sends bytes, and
     * `ServerRequestFactory::fromGlobals()` hands `$_POST` (an empty array) over as the parsed body.
     */
    private static function wire(ServerRequestInterface $request): ServerRequestInterface
    {
        $parsed = $request->getParsedBody();
        if (!is_array($parsed) || $parsed === [] || (string) $request->getBody() !== '') {
            return $request;
        }
        $wired = $request
            ->withBody((new StreamFactory())->createStream(json_encode($parsed, JSON_THROW_ON_ERROR)))
            ->withParsedBody([]);

        return $wired->hasHeader('Content-Type') ? $wired : $wired->withHeader('Content-Type', 'application/json');
    }
}
