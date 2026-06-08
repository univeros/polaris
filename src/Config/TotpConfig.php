<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;

use function in_array;

/**
 * TOTP (RFC 6238) settings for authenticator-app factors.
 */
final readonly class TotpConfig
{
    private const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];

    /**
     * Hard cap on the skew window. RFC 6238 §5.2 recommends at most ±1 step; ±10 (±5 min at the
     * default 30s period) tolerates generous clock drift while keeping a misconfiguration from
     * accepting a wide range of codes at once and weakening brute-force resistance.
     */
    private const int MAX_WINDOW = 10;

    public function __construct(
        public int $digits,
        public int $period,
        public string $algorithm,
        public int $window,
        public string $issuer,
    ) {
        if ($digits < 6 || $digits > 8) {
            throw new InvalidConfigException('auth.otp.totp.digits must be between 6 and 8.');
        }

        if ($period <= 0) {
            throw new InvalidConfigException('auth.otp.totp.period must be a positive integer.');
        }

        if (!in_array($algorithm, self::ALGORITHMS, true)) {
            throw new InvalidConfigException(
                'auth.otp.totp.algorithm must be one of: ' . implode(', ', self::ALGORITHMS) . '.',
            );
        }

        if ($window < 0 || $window > self::MAX_WINDOW) {
            throw new InvalidConfigException(
                'auth.otp.totp.window must be between 0 and ' . self::MAX_WINDOW . '.',
            );
        }

        if ($issuer === '') {
            throw new InvalidConfigException('auth.otp.totp.issuer must be a non-empty string.');
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            digits: (int) ($data['digits'] ?? 6),
            period: (int) ($data['period'] ?? 30),
            algorithm: (string) ($data['algorithm'] ?? 'SHA1'),
            window: (int) ($data['window'] ?? 1),
            issuer: (string) ($data['issuer'] ?? 'Univeros'),
        );
    }
}
