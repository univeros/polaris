<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Mfa\Destination;

final class DestinationTest extends TestCase
{
    public function testMasksAnE164Phone(): void
    {
        self::assertSame('+1 *** *** 0101', Destination::mask(OtpChallenge::CHANNEL_SMS, '+14155550101'));
    }

    public function testMasksAPhoneWithoutAPlusPrefix(): void
    {
        self::assertSame('*** *** 0101', Destination::mask(OtpChallenge::CHANNEL_SMS, '4155550101'));
    }

    public function testMasksAnEmail(): void
    {
        self::assertSame('a***@example.com', Destination::mask(OtpChallenge::CHANNEL_EMAIL, 'ada@example.com'));
    }

    public function testMasksAMalformedEmailToStars(): void
    {
        self::assertSame('***', Destination::mask(OtpChallenge::CHANNEL_EMAIL, 'not-an-email'));
        self::assertSame('***', Destination::mask(OtpChallenge::CHANNEL_EMAIL, '@example.com'));
    }

    public function testEmptyDestinationStaysEmpty(): void
    {
        self::assertSame('', Destination::mask(OtpChallenge::CHANNEL_SMS, ''));
    }
}
