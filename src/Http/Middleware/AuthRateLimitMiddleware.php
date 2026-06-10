<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\MiddlewareInterface;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function array_values;

/**
 * Applies per-group rate limits to the auth endpoints.
 *
 * Polaris's auth flows have different abuse profiles — login guessing, registration spam,
 * password-reset flooding, refresh churn — so each gets its own budget rather than one blanket
 * limit. This middleware holds an ordered list of {@see RateLimitGroup}s and delegates a request
 * to the first group whose rule matches, reusing the framework's fixed-window
 * {@see \Altair\Http\Middleware\RateLimit\RateLimitMiddleware} (and its `X-RateLimit-*` / `429`
 * + `Retry-After` behaviour) for the actual accounting. A request that matches no group passes
 * straight through, unlimited.
 *
 * It sits outermost in the pipeline (before routing and authentication), so it keys on the client
 * IP via {@see \Altair\Http\Middleware\RateLimit\IpKeyResolver}; the complementary per-user
 * budget across authenticated endpoints is {@see AuthenticatedRateLimitMiddleware}, which runs
 * after token authentication.
 */
final class AuthRateLimitMiddleware implements MiddlewareInterface
{
    /** @var list<RateLimitGroup> */
    private readonly array $groups;

    public function __construct(RateLimitGroup ...$groups)
    {
        $this->groups = array_values($groups);
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        foreach ($this->groups as $group) {
            if (($group->rule)($request)) {
                return $group->limiter->process($request, $handler);
            }
        }

        return $handler->handle($request);
    }
}
