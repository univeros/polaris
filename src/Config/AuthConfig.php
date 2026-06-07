<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;

use function in_array;
use function is_array;

/**
 * The typed, validated root of Polaris configuration.
 *
 * Built once at boot from the host's `auth` config namespace (with safe defaults
 * for everything) and bound in the container. Domain services depend on this
 * value object, never on raw arrays. Construction validates every invariant so an
 * invalid configuration fails fast instead of surfacing as a runtime surprise.
 */
final readonly class AuthConfig
{
    private const PASSWORD_ALGOS = ['argon2id', 'argon2i', 'bcrypt'];
    private const TOKEN_DELIVERY = ['body', 'cookie'];

    public function __construct(
        public string $issuer,
        public ?string $audience,
        public AccessTokenConfig $accessToken,
        public RefreshTokenConfig $refreshToken,
        public OtpConfig $otp,
        public int $passwordMinLength,
        public string $passwordAlgo,
        public bool $breachCheck,
        public int $lockoutMaxAttempts,
        public int $lockoutWindow,
        public int $lockoutDuration,
        public bool $mfaEnforce,
        public bool $mfaGraceEnroll,
        public int $stepUpMaxAge,
        public bool $requireVerifiedEmail,
        public string $tokenDelivery,
    ) {
        if ($issuer === '') {
            throw new InvalidConfigException('auth.issuer must be a non-empty string.');
        }

        if ($passwordMinLength < 8) {
            throw new InvalidConfigException('auth.password.min_length must be at least 8.');
        }

        if (!in_array($passwordAlgo, self::PASSWORD_ALGOS, true)) {
            throw new InvalidConfigException(
                'auth.password.algo must be one of: ' . implode(', ', self::PASSWORD_ALGOS) . '.',
            );
        }

        if ($lockoutMaxAttempts <= 0 || $lockoutWindow <= 0 || $lockoutDuration <= 0) {
            throw new InvalidConfigException('auth.lockout values must be positive integers.');
        }

        if ($stepUpMaxAge <= 0) {
            throw new InvalidConfigException('auth.step_up.max_age must be a positive integer.');
        }

        if (!in_array($tokenDelivery, self::TOKEN_DELIVERY, true)) {
            throw new InvalidConfigException(
                'auth.flows.token_delivery must be one of: ' . implode(', ', self::TOKEN_DELIVERY) . '.',
            );
        }
    }

    /**
     * @param array<string, mixed> $auth the host's `auth` config namespace
     */
    public static function fromArray(array $auth): self
    {
        $password = self::section($auth, 'password');
        $lockout = self::section($auth, 'lockout');
        $mfa = self::section($auth, 'mfa');
        $flows = self::section($auth, 'flows');
        $stepUp = self::section($auth, 'step_up');

        return new self(
            issuer: (string) ($auth['issuer'] ?? ''),
            audience: self::nullableString($auth['audience'] ?? null),
            accessToken: AccessTokenConfig::fromArray(self::section($auth, 'access_token')),
            refreshToken: RefreshTokenConfig::fromArray(self::section($auth, 'refresh_token')),
            otp: OtpConfig::fromArray(self::section($auth, 'otp')),
            passwordMinLength: (int) ($password['min_length'] ?? 12),
            passwordAlgo: (string) ($password['algo'] ?? 'argon2id'),
            breachCheck: (bool) ($password['breach_check'] ?? false),
            lockoutMaxAttempts: (int) ($lockout['max_attempts'] ?? 5),
            lockoutWindow: (int) ($lockout['window'] ?? 900),
            lockoutDuration: (int) ($lockout['lock_duration'] ?? 900),
            mfaEnforce: (bool) ($mfa['enforce'] ?? false),
            mfaGraceEnroll: (bool) ($mfa['grace_enroll'] ?? true),
            stepUpMaxAge: (int) ($stepUp['max_age'] ?? 300),
            requireVerifiedEmail: (bool) ($flows['require_verified_email'] ?? true),
            tokenDelivery: (string) ($flows['token_delivery'] ?? 'body'),
        );
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private static function section(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        return is_array($value) ? $value : [];
    }

    private static function nullableString(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string) $value;
    }
}
