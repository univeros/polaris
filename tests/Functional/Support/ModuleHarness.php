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
use Altair\Http\Support\MiddlewarePriority;
use FastRoute\RouteCollector;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Relay\Relay;
use Univeros\Polaris\Module;

use function FastRoute\simpleDispatcher;
use function is_string;
use function usort;

/**
 * A lightweight in-process HTTP kernel for functional tests: it wires a module's `routes()`
 * **and** its contributed `middleware()` into the real framework dispatch pipeline over a
 * configured container, so a PSR-7 request is driven through the actual middleware →
 * Action → Domain → Responder path and a real response comes back.
 *
 * The module's middleware is merged with the base dispatch stages (FastRoute
 * {@see DispatcherMiddleware} → {@see ActionMiddleware}) and ordered by priority exactly as the
 * framework front controller does ({@see \Altair\Http\Support\ModuleMiddleware::entries()}), so
 * the auth + rate-limit middleware run in their production positions — there is no simulation of
 * what the pipeline does.
 *
 * Each route's domain is wrapped in an {@see Action} using the harness {@see JsonResponder} and
 * the framework {@see InputParser}, so a JSON/form body and query/attributes reach the domain as
 * an InputCollection.
 */
final class ModuleHarness
{
    /** @var list<mixed> the priority-ordered middleware queue handed to Relay */
    private readonly array $pipeline;
    private readonly ResponseFactoryInterface $responseFactory;

    public function __construct(Container $container, Module $module)
    {
        $resolver = static fn(string $class): object => $container->get($class);
        $this->responseFactory = $container->get(ResponseFactoryInterface::class);

        $dispatcher = simpleDispatcher(static function (RouteCollector $collector) use ($module): void {
            foreach ($module->routes() as [$method, $path, $domain]) {
                $collector->addRoute($method, $path, new Action($domain, JsonResponder::class, InputParser::class));
            }
        });

        // Merge the base dispatch stages with the module's middleware and stable-sort by priority
        // (lower = more outer), so the pipeline matches the real front controller's order.
        $entries = [
            ['middleware' => new DispatcherMiddleware($dispatcher), 'priority' => MiddlewarePriority::DISPATCHER],
            [
                'middleware' => new ActionMiddleware($resolver, $this->responseFactory),
                'priority' => MiddlewarePriority::ACTION,
            ],
        ];
        foreach ($module->middleware() as $entry) {
            $entries[] = $entry;
        }
        usort($entries, static fn(array $a, array $b): int => $a['priority'] <=> $b['priority']);

        $pipeline = [];
        foreach ($entries as $entry) {
            $middleware = $entry['middleware'];
            $pipeline[] = is_string($middleware) ? $container->get($middleware) : $middleware;
        }

        $this->pipeline = $pipeline;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            return (new Relay($this->pipeline))->handle($request);
        } catch (HttpNotFoundException) {
            return $this->responseFactory->createResponse(404);
        } catch (HttpMethodNotAllowedException) {
            return $this->responseFactory->createResponse(405);
        }
    }
}
