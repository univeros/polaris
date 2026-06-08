<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\CredentialsExtractorInterface;
use Override;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A credentials extractor that never extracts anything.
 *
 * {@see \Altair\Http\Middleware\TokenAuthenticationMiddleware} requires a
 * {@see CredentialsExtractorInterface}; if one returned `username`/`password` from the body the
 * middleware would mint a token directly from raw credentials — bypassing the lockout,
 * verified-email, timing-equalization, and (later) MFA gates enforced by
 * {@see \Univeros\Polaris\Identity\LoginService}. Polaris therefore disables that path: only a
 * pre-issued bearer token authenticates a protected route, and `POST /auth/login` stays the
 * sole credential entry point.
 */
final class NullCredentialsExtractor implements CredentialsExtractorInterface
{
    #[Override]
    public function extract(ServerRequestInterface $request): ?array
    {
        return null;
    }
}
