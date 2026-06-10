<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Middleware\RateLimit\Contracts\KeyResolverInterface;
use Altair\Http\Middleware\RateLimit\IpKeyResolver;
use Override;
use Psr\Http\Message\ServerRequestInterface;

use function is_string;

/**
 * Rate-limit key resolver for authenticated requests: the access token's `sub`, so the budget
 * follows the user across IPs and devices. Falls back to the client IP when the request carries
 * no token (or the token has no subject) — the conservative bucket rather than no bucket.
 */
final readonly class TokenSubjectKeyResolver implements KeyResolverInterface
{
    public function __construct(private IpKeyResolver $fallback = new IpKeyResolver())
    {
    }

    #[Override]
    public function resolve(ServerRequestInterface $request): string
    {
        $token = $request->getAttribute(TokenInterface::TOKEN_KEY);
        if ($token instanceof TokenInterface) {
            $subject = $token->getMetadata('sub');
            if (is_string($subject) && $subject !== '') {
                return 'user:' . $subject;
            }
        }

        return $this->fallback->resolve($request);
    }
}
