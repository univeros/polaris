<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

/**
 * The result of starting an SMS/email factor enrollment: the new (unconfirmed) factor id, the
 * channel, and the **masked** destination the code was sent to (safe to echo back). The code
 * itself is delivered out of band, never returned.
 */
final readonly class OtpFactorEnrollResult
{
    public function __construct(
        public string $factorId,
        public string $channel,
        public string $maskedDestination,
    ) {
    }
}
