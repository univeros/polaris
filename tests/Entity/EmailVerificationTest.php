<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\EmailVerification;

final class EmailVerificationTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $verification = new EmailVerification();

        self::assertSame('', $verification->id);
        self::assertSame('', $verification->userId);
        self::assertSame('', $verification->email);
        self::assertSame('', $verification->tokenHash);
        self::assertNull($verification->consumedAt);
        self::assertNull($verification->ip);
    }
}
