<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\TokenExtractorInterface;
use Override;
use Psr\Http\Message\ServerRequestInterface;

use function preg_match;

/**
 * Pulls the raw JWT out of an `Authorization: Bearer <token>` header.
 *
 * The framework {@see \Altair\Http\Support\HeaderTokenExtractor} returns the whole header value
 * (scheme included), which the JWT parser cannot read; this strips the case-insensitive
 * `Bearer ` scheme and returns just the token. Any other scheme (e.g. `Basic`) yields `null`
 * so non-bearer credentials are never handed to the token factory.
 */
final readonly class BearerTokenExtractor implements TokenExtractorInterface
{
    public function __construct(private string $header = 'Authorization')
    {
    }

    #[Override]
    public function extract(ServerRequestInterface $request): ?string
    {
        $value = $request->getHeader($this->header)[0] ?? '';

        if (preg_match('/^Bearer\s+(\S.*)$/i', $value, $matches) !== 1) {
            return null;
        }

        return trim($matches[1]);
    }
}
