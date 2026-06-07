<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Token\AccessTokenClaims;

/**
 * A token minted by {@see \Univeros\Polaris\Token\PolarisTokenGenerator} carries the
 * full Polaris claim set and a `kid` header, and round-trips through
 * {@see \Univeros\Polaris\Token\PolarisTokenParser} verified against the public key.
 */
final class PolarisTokenRoundTripTest extends TokenTestCase
{
    public function testMintsAndVerifiesTheFullClaimSet(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        $claims = new AccessTokenClaims(
            subject: 'user-123',
            jwtId: 'jti-abc',
            sessionId: 'family-xyz',
            organizationId: 'org-789',
            roles: ['admin', 'member'],
            emailVerified: true,
            mfa: true,
            amr: ['pwd', 'otp'],
            authTime: 1_780_000_000,
        );

        $jwt = $this->generator($config, $clock)->generate($claims->toClaims());
        $token = $this->parser($config, $clock)->parse($jwt);

        self::assertSame('user-123', $token->getMetadata('sub'));
        self::assertSame('jti-abc', $token->getMetadata('jti'));
        self::assertSame('family-xyz', $token->getMetadata('sid'));
        self::assertSame('org-789', $token->getMetadata('org'));
        self::assertSame(['admin', 'member'], $token->getMetadata('roles'));
        self::assertTrue($token->getMetadata('email_verified'));
        self::assertTrue($token->getMetadata('mfa'));
        self::assertSame(['pwd', 'otp'], $token->getMetadata('amr'));
        self::assertSame(1_780_000_000, $token->getMetadata('auth_time'));
        self::assertSame(self::ISSUER, $token->getMetadata('iss'));
    }

    public function testHeaderCarriesTheKeyId(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        $jwt = $this->generator($config, $clock)->generate(
            (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims(),
        );

        $header = $this->header($jwt);
        self::assertSame(self::KID, $header['kid']);
        self::assertSame('RS256', $header['alg']);
    }

    public function testNullableOrgIsCarriedExplicitly(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        $jwt = $this->generator($config, $clock)->generate(
            (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims(),
        );
        $token = $this->parser($config, $clock)->parse($jwt);

        self::assertNull($token->getMetadata('org'));
        self::assertSame([], $token->getMetadata('roles'));
        self::assertFalse($token->getMetadata('email_verified'));
    }
}
