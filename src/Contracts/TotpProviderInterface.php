<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

use SensitiveParameter;

/**
 * Generates and verifies RFC 6238 TOTP secrets/codes for authenticator-app factors.
 *
 * A port over the underlying library ({@see \Univeros\Polaris\Mfa\OtphpTotpProvider} wraps
 * `spomky-labs/otphp`) so the digits/period/algorithm/skew come from {@see \Univeros\Polaris\Config\TotpConfig}
 * and the implementation is swappable. The shared secret is base32; Polaris stores it encrypted.
 */
interface TotpProviderInterface
{
    /**
     * A fresh base32-encoded shared secret for a new factor.
     */
    public function generateSecret(): string;

    /**
     * The `otpauth://totp/...` provisioning URI an authenticator app scans, carrying the secret,
     * issuer, and configured digits/period/algorithm.
     *
     * @param string $accountLabel the account identifier shown in the app (typically the email)
     */
    public function provisioningUri(string $secret, string $accountLabel): string;

    /**
     * Whether `$code` is valid for `$secret` right now, within the configured skew window.
     */
    public function verify(string $secret, #[SensitiveParameter] string $code): bool;

    /**
     * The step-aligned Unix timestamp of the time step whose code matched `$code`, or null when the
     * code is invalid. Callers use the returned step to reject replay: a code from a step already
     * consumed (≤ the last accepted step) must not be honoured again within its validity window.
     */
    public function matchingTimestamp(string $secret, #[SensitiveParameter] string $code): ?int;
}
