<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use RuntimeException;

use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_RSA;

/**
 * Generates RSA keypairs for token tests, cached per-process so the (relatively
 * expensive) key generation runs once regardless of how many tests need keys.
 *
 * Two independent pairs are exposed: {@see rsa()} is the service's keypair, and
 * {@see rsaAlternate()} is an unrelated pair used to prove signature rejection.
 */
final class TestKeys
{
    /** @var array{private: non-empty-string, public: non-empty-string}|null */
    private static ?array $primary = null;

    /** @var array{private: non-empty-string, public: non-empty-string}|null */
    private static ?array $alternate = null;

    /**
     * @return array{private: non-empty-string, public: non-empty-string}
     */
    public static function rsa(): array
    {
        return self::$primary ??= self::generate();
    }

    /**
     * @return array{private: non-empty-string, public: non-empty-string}
     */
    public static function rsaAlternate(): array
    {
        return self::$alternate ??= self::generate();
    }

    /**
     * @return array{private: non-empty-string, public: non-empty-string}
     */
    private static function generate(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false || !openssl_pkey_export($resource, $privatePem)) {
            throw new RuntimeException('Failed to generate an RSA test keypair.');
        }

        $details = openssl_pkey_get_details($resource);
        $publicPem = $details['key'] ?? '';

        if ($privatePem === '' || $publicPem === '') {
            throw new RuntimeException('Generated RSA test keypair is empty.');
        }

        return ['private' => $privatePem, 'public' => $publicPem];
    }
}
