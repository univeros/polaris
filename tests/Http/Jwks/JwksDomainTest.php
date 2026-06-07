<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Jwks;

use Altair\Http\Collection\InputCollection;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Univeros\Polaris\Tests\Support\TestKeys;

/**
 * The JWKS endpoint serves a `200` JWK Set whose single key is the configured public
 * key, advertised under the configured `kid` and signing algorithm.
 */
final class JwksDomainTest extends TestCase
{
    public function testServesThePublicKeyByKid(): void
    {
        $keys = TestKeys::rsa();
        $secrets = new Secrets('app-key', $keys['private'], $keys['public'], 'kid-42');
        $config = AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test']);

        $payload = (new JwksDomain($secrets, $config))(new InputCollection());

        self::assertSame(200, $payload->getStatus());

        $output = $payload->getOutput();
        self::assertIsArray($output['keys']);
        $jwk = $output['keys'][0];
        self::assertIsArray($jwk);
        self::assertSame('kid-42', $jwk['kid']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('RSA', $jwk['kty']);
    }
}
