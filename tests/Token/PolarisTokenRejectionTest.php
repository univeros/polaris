<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Altair\Http\Exception\InvalidTokenException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\TestKeys;
use Univeros\Polaris\Token\AccessTokenClaims;

/**
 * The parser rejects tokens that fail any required constraint: wrong signature,
 * wrong issuer, wrong audience, or outside the validity window.
 */
final class PolarisTokenRejectionTest extends TokenTestCase
{
    private function validJwt(int $ttl = 900): string
    {
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        return $this->generator($this->config(ttl: $ttl), $clock)->generate(
            (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims(),
        );
    }

    public function testRejectsATamperedSignature(): void
    {
        $jwt = $this->validJwt();
        // Parser configured with an unrelated public key cannot verify the signature.
        $foreignConfig = $this->config(publicKey: TestKeys::rsaAlternate()['public']);

        $this->expectException(InvalidTokenException::class);
        $this->parser($foreignConfig, FrozenClock::at('2026-06-07 12:01:00'))->parse($jwt);
    }

    public function testRejectsAWrongIssuer(): void
    {
        $jwt = $this->validJwt();
        $config = $this->config(issuer: 'https://evil.example');

        $this->expectException(InvalidTokenException::class);
        $this->parser($config, FrozenClock::at('2026-06-07 12:01:00'))->parse($jwt);
    }

    public function testRejectsAWrongAudience(): void
    {
        $jwt = $this->validJwt();
        $config = $this->config(audience: 'https://other-api.example');

        $this->expectException(InvalidTokenException::class);
        $this->parser($config, FrozenClock::at('2026-06-07 12:01:00'))->parse($jwt);
    }

    public function testRejectsAnExpiredToken(): void
    {
        $jwt = $this->validJwt(ttl: 60);
        // 10 minutes later the 60s token is well past expiry.
        $config = $this->config(ttl: 60);

        $this->expectException(InvalidTokenException::class);
        $this->parser($config, FrozenClock::at('2026-06-07 12:10:00'))->parse($jwt);
    }

    public function testRejectsATokenUsedBeforeItsNotBeforeTime(): void
    {
        $jwt = $this->validJwt(); // minted (and not-before) at 12:00:00
        $config = $this->config();

        $this->expectException(InvalidTokenException::class);
        $this->parser($config, FrozenClock::at('2026-06-07 11:55:00'))->parse($jwt);
    }

    public function testRejectsAWellSignedTokenThatOmitsExpiry(): void
    {
        // A token that verifies and has the right issuer/audience but carries no `exp`/`iat`
        // would slip past the framework's LooseValidAt as "never expires"; the Polaris parser
        // requires those time claims and rejects it.
        $keys = TestKeys::rsa();
        $lcobucci = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($keys['private']),
            InMemory::plainText($keys['public']),
        );
        $jwt = $lcobucci->builder()
            ->issuedBy(self::ISSUER)
            ->permittedFor(self::AUDIENCE)
            ->relatedTo('user-1')
            ->getToken($lcobucci->signer(), $lcobucci->signingKey())
            ->toString();

        $this->expectException(InvalidTokenException::class);
        $this->parser($this->config(), FrozenClock::at('2026-06-07 12:00:00'))->parse($jwt);
    }

    public function testRejectsAMalformedToken(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->parser($this->config(), FrozenClock::at('2026-06-07 12:00:00'))->parse('not-a-jwt');
    }
}
