<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use SensitiveParameter;

/**
 * The result of starting TOTP enrollment: the new (unconfirmed) factor id, the base32 secret and
 * `otpauth://` URI for manual/scan setup, and a rendered QR. The secret is returned **once** (only
 * until the factor is confirmed) and is never returned again.
 */
final readonly class TotpEnrollResult
{
    public function __construct(
        public string $factorId,
        #[SensitiveParameter] public string $secret,
        #[SensitiveParameter] public string $otpauthUri,
        public string $qrSvg,
    ) {
    }

    /**
     * Keep the secret (and the URI/QR that embed it) out of var_dump/debug output;
     * `#[SensitiveParameter]` only covers stack traces.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'factorId' => $this->factorId,
            'secret' => '[redacted]',
            'otpauthUri' => '[redacted]',
            'qrSvg' => '[redacted]',
        ];
    }
}
