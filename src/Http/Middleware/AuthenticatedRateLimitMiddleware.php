<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Middleware\RateLimit\RateLimitMiddleware;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The global authenticated rate budget (`docs/auth/security.md` §5, issue #97): one
 * fixed-window budget per **user id** across every authenticated endpoint, complementing the
 * per-IP, per-endpoint-group budgets of {@see AuthRateLimitMiddleware}. A per-IP budget alone
 * cannot stop a credentialed abuser rotating through addresses; this one follows the account.
 *
 * It runs after {@see \Altair\Http\Middleware\TokenAuthenticationMiddleware} has attached the
 * access token (so the user id is trustworthy) and keys on the token's `sub` via
 * {@see TokenSubjectKeyResolver}. Requests without a token pass straight through — the
 * unauthenticated endpoints carry their own per-IP budgets upstream.
 */
final readonly class AuthenticatedRateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(private RateLimitMiddleware $limiter)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$request->getAttribute(TokenInterface::TOKEN_KEY) instanceof TokenInterface) {
            return $handler->handle($request);
        }

        return $this->limiter->process($request, $handler);
    }
}
