<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The `onError` handler for {@see \Altair\Http\Middleware\TokenAuthenticationMiddleware}.
 *
 * The framework returns a bare `403` for a *missing* token and `401` for an *invalid* one. Both
 * are authentication failures, for which RFC 7235 prescribes `401`; this normalises every auth
 * failure to a `401` carrying the same JSON envelope the protected domains emit
 * ({@see \Univeros\Polaris\Http\Auth\AuthDomain::unauthorized()}) plus a `WWW-Authenticate`
 * challenge, so a rejected request looks the same whether the middleware or a domain produced it.
 */
final class UnauthorizedResponder
{
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        ?Throwable $exception = null,
    ): ResponseInterface {
        $response->getBody()->write(json_encode([
            'error' => 'unauthorized',
            'message' => 'Authentication is required.',
        ], JSON_THROW_ON_ERROR));

        return $response
            ->withStatus(401)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('WWW-Authenticate', 'Bearer');
    }
}
