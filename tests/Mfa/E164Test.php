<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Mfa\E164;

final class E164Test extends TestCase
{
    public function testAcceptsValidE164Numbers(): void
    {
        self::assertTrue(E164::isValid('+14155550101'));
        self::assertTrue(E164::isValid('+442071234567'));
        self::assertTrue(E164::isValid('+8613800138000'));
    }

    public function testRejectsInvalidNumbers(): void
    {
        self::assertFalse(E164::isValid(''));
        self::assertFalse(E164::isValid('4155550101'), 'missing +');
        self::assertFalse(E164::isValid('+0155550101'), 'leading zero after +');
        self::assertFalse(E164::isValid('+1 415 555 0101'), 'spaces');
        self::assertFalse(E164::isValid('+1-415-555-0101'), 'dashes');
        self::assertFalse(E164::isValid('+1234567890123456'), 'more than 15 digits');
        self::assertFalse(E164::isValid('+12'), 'shorter than the 7-digit practical minimum');
        self::assertFalse(E164::isValid('+'), 'no digits');
    }
}
