<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

/**
 * The result of issuing an OTP challenge: the challenge id, the channel it was sent over, and the
 * **masked** destination safe to echo back to the client (e.g. `+1 *** *** 0101`). The code itself
 * is never returned — it is delivered out of band via SMS/email.
 */
final readonly class OtpChallengeResult
{
    public function __construct(
        public string $challengeId,
        public string $channel,
        public string $maskedDestination,
    ) {
    }
}
