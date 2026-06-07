<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Token\AccessTokenClaims;

use function array_key_exists;

final class AccessTokenClaimsTest extends TestCase
{
    public function testRendersTheFullClaimMap(): void
    {
        $claims = (new AccessTokenClaims(
            subject: 'user-1',
            jwtId: 'jti-1',
            sessionId: 'sid-1',
            organizationId: 'org-1',
            roles: ['admin'],
            scope: ['members.invite'],
            emailVerified: true,
            mfa: true,
            amr: ['pwd', 'otp'],
            authTime: 1_780_000_000,
        ))->toClaims();

        self::assertSame('user-1', $claims['sub']);
        self::assertSame('jti-1', $claims['jti']);
        self::assertSame('sid-1', $claims['sid']);
        self::assertSame('org-1', $claims['org']);
        self::assertSame(['admin'], $claims['roles']);
        self::assertSame(['members.invite'], $claims['scope']);
        self::assertTrue($claims['email_verified']);
        self::assertTrue($claims['mfa']);
        self::assertSame(['pwd', 'otp'], $claims['amr']);
        self::assertSame(1_780_000_000, $claims['auth_time']);
    }

    public function testOmitsOptionalClaimsButKeepsNullableOrg(): void
    {
        $claims = (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims();

        self::assertFalse(array_key_exists('sid', $claims));
        self::assertFalse(array_key_exists('scope', $claims));
        self::assertFalse(array_key_exists('auth_time', $claims));
        self::assertTrue(array_key_exists('org', $claims));
        self::assertNull($claims['org']);
    }

    public function testRejectsAnEmptySubject(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $claims = new AccessTokenClaims(subject: '', jwtId: 'jti-1');
        self::assertInstanceOf(AccessTokenClaims::class, $claims);
    }

    public function testRejectsAnEmptyJwtId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $claims = new AccessTokenClaims(subject: 'user-1', jwtId: '');
        self::assertInstanceOf(AccessTokenClaims::class, $claims);
    }
}
