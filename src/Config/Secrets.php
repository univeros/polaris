<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Security\Pepper;

use function hash;
use function implode;
use function is_string;
use function strlen;
use function trim;

/**
 * The cryptographic secrets Polaris requires at boot, validated from the environment.
 *
 * These are never defaulted: a host that has not provided the application key and a
 * JWT signing keypair gets a clear startup failure rather than an insecure fallback.
 */
final readonly class Secrets
{
    public function __construct(
        public string $appKey,
        public string $jwtPrivateKey,
        public string $jwtPublicKey,
        public string $jwtKid,
        public ?string $jwtPreviousPublicKey = null,
        public ?string $jwtPreviousKid = null,
    ) {
    }

    /**
     * @param array<string, mixed> $env
     *
     * @throws InvalidConfigException when any required secret is absent or empty
     */
    public static function fromEnvironment(array $env): self
    {
        $appKey = self::read($env, 'APP_KEY');
        $privateKey = self::read($env, 'AUTH_JWT_PRIVATE_KEY');
        $publicKey = self::read($env, 'AUTH_JWT_PUBLIC_KEY');

        $missing = [];
        if ($appKey === '') {
            $missing[] = 'APP_KEY';
        }
        if ($privateKey === '') {
            $missing[] = 'AUTH_JWT_PRIVATE_KEY';
        }
        if ($publicKey === '') {
            $missing[] = 'AUTH_JWT_PUBLIC_KEY';
        }

        if ($missing !== []) {
            throw new InvalidConfigException(
                'Missing required Polaris secrets: ' . implode(', ', $missing) . '.',
            );
        }

        // Everything keyed off APP_KEY (Pepper's HKDF contexts) is only as strong as the key
        // itself, so a short key is a boot failure, not a warning.
        if (strlen($appKey) < Pepper::MIN_KEY_BYTES) {
            throw new InvalidConfigException(
                'APP_KEY must be at least ' . Pepper::MIN_KEY_BYTES . ' bytes (got ' . strlen($appKey) . ').',
            );
        }

        $kid = self::read($env, 'AUTH_JWT_KID');
        if ($kid === '') {
            $kid = hash('sha256', $publicKey);
        }

        // During a key rotation the retiring public key stays published in the JWKS for one
        // access-TTL window (docs/auth/key-rotation.md); both are optional outside that window.
        $previousKey = self::read($env, 'AUTH_JWT_PREVIOUS_PUBLIC_KEY');
        $previousKid = self::read($env, 'AUTH_JWT_PREVIOUS_KID');
        if ($previousKey !== '' && $previousKid === '') {
            $previousKid = hash('sha256', $previousKey);
        }

        return new self(
            $appKey,
            $privateKey,
            $publicKey,
            $kid,
            $previousKey === '' ? null : $previousKey,
            $previousKey === '' ? null : $previousKid,
        );
    }

    /**
     * @param array<string, mixed> $env
     */
    private static function read(array $env, string $key): string
    {
        $value = $env[$key] ?? '';

        return is_string($value) ? trim($value) : '';
    }
}
