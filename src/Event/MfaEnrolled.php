<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user confirms their first MFA factor (`mfa.enrolled`). Carries only identifiers —
 * never the secret or the recovery codes — so audit/notification listeners can react safely.
 */
final readonly class MfaEnrolled
{
    public const string NAME = 'mfa.enrolled';

    public function __construct(
        public string $userId,
        public string $factorId,
        public string $type = '',
    ) {
    }
}
