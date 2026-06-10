<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted on a failed OTP verification (`mfa.otp_verify_failed`) so the host can audit and alert on
 * brute-force attempts. Carries only identifiers — never the submitted code.
 */
final readonly class OtpVerifyFailed
{
    public const string NAME = 'mfa.otp_verify_failed';

    public function __construct(
        public string $userId,
        public string $factorId,
        public ?int $attemptsLeft = null,
    ) {
    }
}
