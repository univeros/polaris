<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an administrator re-enables a previously disabled user account (`user.enabled`).
 */
final readonly class UserEnabled
{
    public const string NAME = 'user.enabled';

    public function __construct(
        public string $userId,
        public string $actorUserId,
    ) {
    }
}
