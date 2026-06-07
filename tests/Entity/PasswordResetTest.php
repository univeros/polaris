<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\PasswordReset;

final class PasswordResetTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $reset = new PasswordReset();

        self::assertSame('', $reset->id);
        self::assertSame('', $reset->userId);
        self::assertSame('', $reset->email);
        self::assertSame('', $reset->tokenHash);
        self::assertNull($reset->consumedAt);
        self::assertNull($reset->ip);
    }
}
