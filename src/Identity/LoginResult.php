<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Univeros\Polaris\Token\IssuedTokens;

/**
 * The outcome of a successful login: the issued token pair plus the minimal user fields
 * the response echoes back (no entity is exposed to the HTTP layer).
 */
final readonly class LoginResult
{
    public function __construct(
        public string $userId,
        public string $email,
        public bool $emailVerified,
        public IssuedTokens $tokens,
    ) {
    }
}
