<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Rule;

use Altair\Http\Contracts\HttpAuthRuleInterface;
use Override;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matches when **any** of the wrapped rules matches — the logical OR of {@see HttpAuthRuleInterface}s.
 * Lets a single rule-taking middleware ({@see \Univeros\Polaris\Http\Middleware\StepUpMiddleware})
 * cover a heterogeneous set of routes (e.g. a few path prefixes plus one method-specific route).
 */
final readonly class AnyRule implements HttpAuthRuleInterface
{
    /** @var list<HttpAuthRuleInterface> */
    private array $rules;

    public function __construct(HttpAuthRuleInterface ...$rules)
    {
        $this->rules = $rules;
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): bool
    {
        foreach ($this->rules as $rule) {
            if ($rule($request)) {
                return true;
            }
        }

        return false;
    }
}
