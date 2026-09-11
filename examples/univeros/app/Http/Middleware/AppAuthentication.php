<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The framework's `TokenAuthenticationMiddleware`, as the Polaris module binds it (bearer tokens
 * only, a 401 envelope on failure, `ssl => false` behind TLS termination), scoped to `/app` by
 * the `RequestPathRule` {@see \App\AppModule} passes to `Container::make()`.
 */
final readonly class AppAuthentication implements MiddlewareInterface
{
    public function __construct(private MiddlewareInterface $authentication)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->authentication->process($request, $handler);
    }
}
