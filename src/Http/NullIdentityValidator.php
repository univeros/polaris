<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http;

use Altair\Http\Contracts\IdentityValidatorInterface;
use Override;

/**
 * The {@see IdentityValidatorInterface} the framework's `TokenAuthenticationMiddleware` requires
 * when the host binds none. It never validates anything: with {@see NullCredentialsExtractor}
 * the middleware never sees credentials, and `POST /auth/login` stays the sole credential entry
 * point (lockout, verified email, MFA).
 */
final class NullIdentityValidator implements IdentityValidatorInterface
{
    #[Override]
    public function __invoke(array $arguments): bool
    {
        return false;
    }
}
