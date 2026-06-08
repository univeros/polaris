<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional\Support;

use Altair\Container\Container;
use Altair\Http\Base\Action;
use Altair\Http\Base\InputParser;
use Altair\Http\Exception\HttpMethodNotAllowedException;
use Altair\Http\Exception\HttpNotFoundException;
use Altair\Http\Middleware\ActionMiddleware;
use Altair\Http\Middleware\DispatcherMiddleware;
use FastRoute\Dispatcher;
use FastRoute\RouteCollector;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Relay\Relay;

use function FastRoute\simpleDispatcher;

/**
 * A lightweight in-process HTTP kernel for functional tests: it wires a module's
 * `routes()` into the real framework dispatch pipeline (FastRoute →
 * {@see DispatcherMiddleware} → {@see ActionMiddleware}) over a configured container, so a
 * PSR-7 request is driven through the actual Action → Domain → Responder path and a real
 * response comes back.
 *
 * Each route's domain is wrapped in an {@see Action} using the harness {@see JsonResponder}
 * and the framework {@see InputParser}, so a JSON/form body and query/attributes reach the
 * domain as an InputCollection.
 */
final class ModuleHarness
{
    private readonly Dispatcher $dispatcher;
    private readonly DispatcherMiddleware $dispatcherMiddleware;
    private readonly ActionMiddleware $actionMiddleware;
    private readonly ResponseFactoryInterface $responseFactory;

    /**
     * @param list<array{0: string, 1: string, 2: class-string}> $routes
     */
    public function __construct(Container $container, array $routes)
    {
        $resolver = static fn(string $class): object => $container->get($class);
        $this->responseFactory = $container->get(ResponseFactoryInterface::class);

        $this->dispatcher = simpleDispatcher(static function (RouteCollector $collector) use ($routes): void {
            foreach ($routes as [$method, $path, $domain]) {
                $collector->addRoute($method, $path, new Action($domain, JsonResponder::class, InputParser::class));
            }
        });

        $this->dispatcherMiddleware = new DispatcherMiddleware($this->dispatcher);
        $this->actionMiddleware = new ActionMiddleware($resolver, $this->responseFactory);
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            return (new Relay([$this->dispatcherMiddleware, $this->actionMiddleware]))->handle($request);
        } catch (HttpNotFoundException) {
            return $this->responseFactory->createResponse(404);
        } catch (HttpMethodNotAllowedException) {
            return $this->responseFactory->createResponse(405);
        }
    }
}
