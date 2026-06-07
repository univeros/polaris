<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Tests\Support\TestKeys;
use Univeros\Polaris\Token\JwkSet;

use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_EC;

final class JwkSetTest extends TestCase
{
    public function testRendersAnRsaPublicKeyAsAJwkKeyedByKid(): void
    {
        $jwks = JwkSet::fromPublicKey(TestKeys::rsa()['public'], 'kid-42', 'RS256');

        self::assertCount(1, $jwks['keys']);
        $jwk = $jwks['keys'][0];

        self::assertSame('RSA', $jwk['kty']);
        self::assertSame('sig', $jwk['use']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('kid-42', $jwk['kid']);
        self::assertNotSame('', $jwk['n']);
        self::assertNotSame('', $jwk['e']);
        // RFC 7515 base64url: no '+', '/', or '=' padding.
        self::assertDoesNotMatchRegularExpression('#[+/=]#', $jwk['n']);
        self::assertDoesNotMatchRegularExpression('#[+/=]#', $jwk['e']);
    }

    public function testRejectsAnUnparseablePublicKey(): void
    {
        $this->expectException(InvalidConfigException::class);
        JwkSet::fromPublicKey('-----BEGIN PUBLIC KEY-----not a key-----END PUBLIC KEY-----', 'kid-1', 'RS256');
    }

    public function testRejectsAValidNonRsaKey(): void
    {
        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($resource === false) {
            self::markTestSkipped('OpenSSL EC key generation is unavailable.');
        }

        $details = openssl_pkey_get_details($resource);
        $publicKey = $details['key'] ?? '';

        $this->expectException(InvalidConfigException::class);
        JwkSet::fromPublicKey($publicKey, 'kid-1', 'ES256');
    }
}
