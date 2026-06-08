<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\HttpAuthRuleInterface;
use Altair\Http\Middleware\RateLimit\RateLimitMiddleware;

/**
 * One rate-limit group: the {@see HttpAuthRuleInterface} that decides whether a request belongs
 * to the group (typically a {@see \Altair\Http\Rule\RequestPathRule} over the group's paths) and
 * the framework {@see RateLimitMiddleware} that enforces the group's budget.
 *
 * {@see AuthRateLimitMiddleware} holds an ordered list of these and delegates a request to the
 * first group whose rule matches.
 */
final readonly class RateLimitGroup
{
    public function __construct(
        public HttpAuthRuleInterface $rule,
        public RateLimitMiddleware $limiter,
    ) {
    }
}
