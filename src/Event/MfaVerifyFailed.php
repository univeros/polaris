<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an MFA verification attempt at the login gate fails (`mfa.verify_failed`) — a wrong
 * or expired code, an unknown factor, or an unusable recovery code. Carries only the user id so
 * audit/abuse listeners can react without ever seeing the rejected secret. The channel-level
 * {@see OtpVerifyFailed} still fires for sms/email; this is the gate-level signal across every
 * factor type.
 */
final readonly class MfaVerifyFailed
{
    public const string NAME = 'mfa.verify_failed';

    /** `type` for the factor-less recovery-code path. */
    public const string TYPE_RECOVERY = 'recovery';

    public function __construct(
        public string $userId,
        public ?string $factorId = null,
        public ?string $type = null,
    ) {
    }
}
