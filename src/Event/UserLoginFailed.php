<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted on a failed password login for a known user (`user.login_failed`). High-signal
 * for alerting on credential-stuffing; the failed-attempt counter drives lockout.
 */
final readonly class UserLoginFailed
{
    public const string NAME = 'user.login_failed';

    public function __construct(
        public string $userId,
        public ?string $ip = null,
    ) {
    }
}
