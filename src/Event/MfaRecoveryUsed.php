<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a recovery code is spent to authenticate (`mfa.recovery_used`) — a high-value
 * signal to the user: someone just signed in without their primary factor.
 */
final readonly class MfaRecoveryUsed
{
    public const string NAME = 'mfa.recovery_used';

    public function __construct(
        public string $userId,
        public int $remaining,
    ) {
    }
}
