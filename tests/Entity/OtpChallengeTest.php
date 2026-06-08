<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\OtpChallenge;

final class OtpChallengeTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $challenge = new OtpChallenge();

        self::assertSame('', $challenge->id);
        self::assertSame('', $challenge->userId);
        self::assertNull($challenge->factorId);
        self::assertSame('', $challenge->purpose);
        self::assertSame('', $challenge->channel);
        self::assertNull($challenge->codeHash);
        self::assertNull($challenge->destination);
        self::assertSame(0, $challenge->attempts);
        self::assertSame(5, $challenge->maxAttempts);
        self::assertNull($challenge->consumedAt);
        self::assertNull($challenge->ip);
    }

    public function testExposesPurposeAndChannelValues(): void
    {
        self::assertSame('login_mfa', OtpChallenge::PURPOSE_LOGIN_MFA);
        self::assertSame('email_verify', OtpChallenge::PURPOSE_EMAIL_VERIFY);
        self::assertSame('totp', OtpChallenge::CHANNEL_TOTP);
        self::assertSame(5, OtpChallenge::DEFAULT_MAX_ATTEMPTS);
    }
}
