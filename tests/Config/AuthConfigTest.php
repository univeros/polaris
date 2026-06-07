<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Config;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Exception\InvalidConfigException;

final class AuthConfigTest extends TestCase
{
    public function testAppliesDocumentedDefaults(): void
    {
        $config = AuthConfig::fromArray(['issuer' => 'https://auth.example.com']);

        self::assertSame('https://auth.example.com', $config->issuer);
        self::assertNull($config->audience);
        self::assertSame(900, $config->accessToken->ttl);
        self::assertSame('RS256', $config->accessToken->signer);
        self::assertSame(2592000, $config->refreshToken->ttl);
        self::assertTrue($config->refreshToken->rotation);
        self::assertTrue($config->refreshToken->reuseDetection);
        self::assertSame(6, $config->otp->length);
        self::assertSame(300, $config->otp->ttl);
        self::assertSame(6, $config->otp->totp->digits);
        self::assertSame(30, $config->otp->totp->period);
        self::assertSame('SHA1', $config->otp->totp->algorithm);
        self::assertSame(12, $config->passwordMinLength);
        self::assertSame('argon2id', $config->passwordAlgo);
        self::assertSame('body', $config->tokenDelivery);
        self::assertSame(300, $config->stepUpMaxAge);
        self::assertTrue($config->requireVerifiedEmail);
        self::assertFalse($config->mfaEnforce);
    }

    public function testAppliesOverrides(): void
    {
        $config = AuthConfig::fromArray([
            'issuer' => 'acme',
            'audience' => 'https://api.acme.test',
            'access_token' => ['ttl' => 600, 'signer' => 'EdDSA'],
            'refresh_token' => ['ttl' => 86400, 'rotation' => false],
            'otp' => ['length' => 8, 'totp' => ['digits' => 8, 'algorithm' => 'SHA256', 'issuer' => 'Acme']],
            'password' => ['min_length' => 16, 'algo' => 'bcrypt'],
            'mfa' => ['enforce' => true],
            'flows' => ['token_delivery' => 'cookie', 'require_verified_email' => false],
        ]);

        self::assertSame('https://api.acme.test', $config->audience);
        self::assertSame(600, $config->accessToken->ttl);
        self::assertSame('EdDSA', $config->accessToken->signer);
        self::assertFalse($config->refreshToken->rotation);
        self::assertSame(8, $config->otp->length);
        self::assertSame(8, $config->otp->totp->digits);
        self::assertSame('SHA256', $config->otp->totp->algorithm);
        self::assertSame(16, $config->passwordMinLength);
        self::assertSame('bcrypt', $config->passwordAlgo);
        self::assertTrue($config->mfaEnforce);
        self::assertSame('cookie', $config->tokenDelivery);
        self::assertFalse($config->requireVerifiedEmail);
    }

    public function testRejectsEmptyIssuer(): void
    {
        $this->expectException(InvalidConfigException::class);

        AuthConfig::fromArray([]);
    }

    public function testRejectsUnknownSigner(): void
    {
        $this->expectException(InvalidConfigException::class);

        AuthConfig::fromArray(['issuer' => 'x', 'access_token' => ['signer' => 'HS256']]);
    }

    public function testRejectsWeakPasswordPolicy(): void
    {
        $this->expectException(InvalidConfigException::class);

        AuthConfig::fromArray(['issuer' => 'x', 'password' => ['min_length' => 4]]);
    }

    public function testRejectsUnknownTokenDelivery(): void
    {
        $this->expectException(InvalidConfigException::class);

        AuthConfig::fromArray(['issuer' => 'x', 'flows' => ['token_delivery' => 'header']]);
    }

    public function testRejectsInvalidTotpDigits(): void
    {
        $this->expectException(InvalidConfigException::class);

        AuthConfig::fromArray(['issuer' => 'x', 'otp' => ['totp' => ['digits' => 9]]]);
    }
}
