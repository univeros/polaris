<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use OTPHP\TOTP;
use Override;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Univeros\Polaris\Config\TotpConfig;
use Univeros\Polaris\Contracts\TotpProviderInterface;

use function hash_equals;
use function strtolower;

/**
 * RFC 6238 TOTP via `spomky-labs/otphp`, configured from {@see TotpConfig}.
 *
 * Verification checks the current time step plus the configured skew window on each side
 * (`±window` periods), comparing in constant time — otphp's own `verify()` expresses tolerance
 * in seconds (which cannot span a whole period), so the step window is applied here over
 * `TOTP::at()`. The injected {@see ClockInterface} keeps generation and verification deterministic
 * and testable.
 */
final readonly class OtphpTotpProvider implements TotpProviderInterface
{
    public function __construct(
        private TotpConfig $config,
        private ClockInterface $clock,
    ) {
    }

    #[Override]
    public function generateSecret(): string
    {
        return TOTP::generate($this->clock)->getSecret();
    }

    #[Override]
    public function provisioningUri(string $secret, string $accountLabel): string
    {
        $totp = $this->totp($secret);
        $totp->setLabel($accountLabel);

        return $totp->getProvisioningUri();
    }

    #[Override]
    public function verify(string $secret, #[SensitiveParameter] string $code): bool
    {
        if ($code === '') {
            return false;
        }

        $totp = $this->totp($secret);
        $now = $this->clock->now()->getTimestamp();
        $period = $this->config->period;

        for ($step = -$this->config->window; $step <= $this->config->window; ++$step) {
            $timestamp = $now + ($step * $period);
            if ($timestamp < 0) {
                continue;
            }

            if (hash_equals($totp->at($timestamp), $code)) {
                return true;
            }
        }

        return false;
    }

    private function totp(string $secret): TOTP
    {
        $totp = TOTP::createFromSecret($secret, $this->clock);
        $totp->setPeriod($this->config->period);
        $totp->setDigits($this->config->digits);
        // otphp validates the digest against hash_algos(), which are lower-case.
        $totp->setDigest(strtolower($this->config->algorithm));
        $totp->setIssuer($this->config->issuer);

        return $totp;
    }
}
