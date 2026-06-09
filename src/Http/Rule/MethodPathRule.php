<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Rule;

use Altair\Http\Contracts\HttpAuthRuleInterface;
use Override;
use Psr\Http\Message\ServerRequestInterface;

use function strtoupper;

/**
 * Narrows another {@see HttpAuthRuleInterface} to a single HTTP method — so a guard can target, say,
 * `DELETE /auth/mfa/factors/{id}` without also catching `GET`/`PATCH` on the same path.
 */
final readonly class MethodPathRule implements HttpAuthRuleInterface
{
    public function __construct(
        private string $method,
        private HttpAuthRuleInterface $path,
    ) {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): bool
    {
        return strtoupper($request->getMethod()) === strtoupper($this->method) && ($this->path)($request);
    }
}
