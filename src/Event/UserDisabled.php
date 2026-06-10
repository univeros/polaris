<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an administrator disables a user account (`user.disabled`); the user's sessions
 * are revoked in the same operation.
 */
final readonly class UserDisabled
{
    public const string NAME = 'user.disabled';

    public function __construct(
        public string $userId,
        public string $actorUserId,
    ) {
    }
}
