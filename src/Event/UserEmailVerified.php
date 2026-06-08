<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user's email address is confirmed (`user.email_verified`).
 */
final readonly class UserEmailVerified
{
    public const string NAME = 'user.email_verified';

    public function __construct(
        public string $userId,
        public string $email,
    ) {
    }
}
