<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;

use function hash;
use function implode;
use function is_string;
use function substr;
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

        $kid = self::read($env, 'AUTH_JWT_KID');
        if ($kid === '') {
            $kid = substr(hash('sha256', $publicKey), 0, 16);
        }

        return new self($appKey, $privateKey, $publicKey, $kid);
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
