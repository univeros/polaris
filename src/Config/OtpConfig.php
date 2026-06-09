<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;

use function is_array;

/**
 * One-time-password settings shared by SMS and email channels, plus the nested TOTP config.
 */
final readonly class OtpConfig
{
    public function __construct(
        public int $length,
        public int $ttl,
        public int $maxAttempts,
        public int $resendCooldown,
        public int $sendMax,
        public int $sendWindow,
        public TotpConfig $totp,
    ) {
        if ($length < 4 || $length > 10) {
            throw new InvalidConfigException('auth.otp.length must be between 4 and 10.');
        }

        if ($ttl <= 0) {
            throw new InvalidConfigException('auth.otp.ttl must be a positive integer.');
        }

        if ($maxAttempts <= 0) {
            throw new InvalidConfigException('auth.otp.max_attempts must be a positive integer.');
        }

        if ($resendCooldown < 0) {
            throw new InvalidConfigException('auth.otp.resend_cooldown must be zero or greater.');
        }

        if ($sendMax <= 0 || $sendWindow <= 0) {
            throw new InvalidConfigException('auth.otp.send_max and auth.otp.send_window must be positive integers.');
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $totp = $data['totp'] ?? null;

        return new self(
            length: (int) ($data['length'] ?? 6),
            ttl: (int) ($data['ttl'] ?? 300),
            maxAttempts: (int) ($data['max_attempts'] ?? 5),
            resendCooldown: (int) ($data['resend_cooldown'] ?? 30),
            sendMax: (int) ($data['send_max'] ?? 5),
            sendWindow: (int) ($data['send_window'] ?? 3600),
            totp: TotpConfig::fromArray(is_array($totp) ? $totp : []),
        );
    }
}
