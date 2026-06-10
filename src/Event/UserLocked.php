<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use DateTimeImmutable;

/**
 * Emitted when repeated failed logins lock an account (`user.locked`). The lock is
 * time-boxed (auto-unlocks once `locked_until` passes).
 */
final readonly class UserLocked
{
    public const string NAME = 'user.locked';

    public function __construct(
        public string $userId,
        public ?string $ip = null,
        public ?DateTimeImmutable $until = null,
    ) {
    }
}
