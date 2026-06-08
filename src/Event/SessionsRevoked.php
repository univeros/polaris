<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when every session for a user is revoked at once — logout-all, or after a
 * password change/reset (`auth.sessions_revoked`).
 */
final readonly class SessionsRevoked
{
    public const string NAME = 'auth.sessions_revoked';

    public function __construct(
        public string $userId,
        public ?string $ip = null,
    ) {
    }
}
