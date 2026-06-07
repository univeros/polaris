<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Identity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Identity\PasswordPolicy;

use function str_repeat;

final class PasswordPolicyTest extends TestCase
{
    public function testAcceptsAPasswordMeetingTheMinimumLength(): void
    {
        self::assertSame([], (new PasswordPolicy(12))->validate('correct horse battery staple'));
    }

    public function testRejectsAShortPassword(): void
    {
        $violations = (new PasswordPolicy(12))->validate('short');

        self::assertCount(1, $violations);
        self::assertStringContainsString('12', $violations[0]);
    }

    public function testCountsCharactersNotBytes(): void
    {
        // 12 multi-byte characters satisfy a 12-character minimum.
        self::assertSame([], (new PasswordPolicy(12))->validate(str_repeat('é', 12)));
    }
}
