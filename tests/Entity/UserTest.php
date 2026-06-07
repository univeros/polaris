<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\User;

final class UserTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $user = new User();

        self::assertSame('', $user->id);
        self::assertSame('', $user->email);
        self::assertSame('active', $user->status);
        self::assertFalse($user->mfaEnforced);
        self::assertSame(0, $user->failedLoginCount);
        self::assertNull($user->emailVerifiedAt);
        self::assertNull($user->passwordHash);
        self::assertNull($user->displayName);
        self::assertNull($user->lockedUntil);
        self::assertNull($user->lastLoginAt);
    }
}
