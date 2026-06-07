<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Security;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Security\Argon2idPasswordHasher;

use function password_hash;

use const PASSWORD_ARGON2ID;
use const PASSWORD_BCRYPT;

final class Argon2idPasswordHasherTest extends TestCase
{
    private function hasher(): Argon2idPasswordHasher
    {
        // Low cost keeps the suite fast; production uses the documented defaults.
        return new Argon2idPasswordHasher(['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]);
    }

    public function testHashesAndVerifies(): void
    {
        $hasher = $this->hasher();
        $hash = $hasher->hash('correct horse battery staple');

        self::assertNotSame('correct horse battery staple', $hash);
        self::assertStringStartsWith('$argon2id$', $hash);
        self::assertTrue($hasher->verify('correct horse battery staple', $hash));
        self::assertFalse($hasher->verify('wrong password', $hash));
    }

    public function testHashesAreSaltedAndUnique(): void
    {
        $hasher = $this->hasher();

        self::assertNotSame($hasher->hash('same'), $hasher->hash('same'));
    }

    public function testRejectsEmptyHashOnVerify(): void
    {
        self::assertFalse($this->hasher()->verify('anything', ''));
    }

    public function testFreshHashDoesNotNeedRehash(): void
    {
        $hasher = $this->hasher();

        self::assertFalse($hasher->needsRehash($hasher->hash('secret')));
    }

    public function testRehashNeededWhenAlgorithmDiffers(): void
    {
        $bcrypt = password_hash('secret', PASSWORD_BCRYPT);

        self::assertTrue($this->hasher()->needsRehash($bcrypt));
    }

    public function testRehashNeededWhenCostIncreases(): void
    {
        $weak = password_hash('secret', PASSWORD_ARGON2ID, ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]);
        $stronger = new Argon2idPasswordHasher(['memory_cost' => 16384, 'time_cost' => 2, 'threads' => 1]);

        self::assertTrue($stronger->needsRehash($weak));
    }
}
