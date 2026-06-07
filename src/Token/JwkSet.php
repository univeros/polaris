<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Univeros\Polaris\Exception\InvalidConfigException;

use function base64_encode;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function rtrim;
use function strtr;

/**
 * Renders a public signing key as a JWK Set ({@see https://www.rfc-editor.org/rfc/rfc7517})
 * for the `/auth/.well-known/jwks.json` endpoint, so resource servers can fetch the key
 * by `kid` and verify access tokens without sharing the private key.
 *
 * RSA keys (the default RS256 signer) are supported. EdDSA/OKP rendering is a follow-up;
 * an unsupported key type fails fast rather than serving a malformed key set.
 */
final class JwkSet
{
    /**
     * @return array{keys: list<array<string, string>>}
     */
    public static function fromPublicKey(string $publicKeyPem, string $keyId, string $algorithm): array
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new InvalidConfigException('The JWT public key could not be parsed for JWKS.');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new InvalidConfigException('JWKS rendering currently supports RSA public keys only.');
        }

        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => $algorithm,
                    'kid' => $keyId,
                    'n' => self::base64UrlEncode((string) $details['rsa']['n']),
                    'e' => self::base64UrlEncode((string) $details['rsa']['e']),
                ],
            ],
        ];
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
