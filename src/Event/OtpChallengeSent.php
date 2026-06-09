<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an OTP code is sent for a factor (`mfa.otp_challenge_sent`). Carries only
 * identifiers and the channel — never the code or the destination — so audit listeners can record
 * it safely.
 */
final readonly class OtpChallengeSent
{
    public const string NAME = 'mfa.otp_challenge_sent';

    public function __construct(
        public string $userId,
        public string $factorId,
        public string $channel,
    ) {
    }
}
