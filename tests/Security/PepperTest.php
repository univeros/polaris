<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Security;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Security\Pepper;

use function ctype_xdigit;
use function strlen;

final class PepperTest extends TestCase
{
    private function pepper(): Pepper
    {
        return new Pepper('application-key-for-tests-0123456789');
    }

    public function testProducesHexSha256Digest(): void
    {
        $hash = $this->pepper()->hash('refresh', 'token-value');

        self::assertSame(64, strlen($hash));
        self::assertTrue(ctype_xdigit($hash));
    }

    public function testIsDeterministicForSameInputs(): void
    {
        self::assertSame(
            $this->pepper()->hash('otp', '123456'),
            $this->pepper()->hash('otp', '123456'),
        );
    }

    public function testDiffersByContext(): void
    {
        $pepper = $this->pepper();

        self::assertNotSame(
            $pepper->hash('refresh', 'same-value'),
            $pepper->hash('otp', 'same-value'),
        );
    }

    public function testDiffersByValue(): void
    {
        $pepper = $this->pepper();

        self::assertNotSame($pepper->hash('otp', '111111'), $pepper->hash('otp', '222222'));
    }

    public function testMatchesValidatesInConstantTime(): void
    {
        $pepper = $this->pepper();
        $hash = $pepper->hash('recovery', 'abcde-fghij');

        self::assertTrue($pepper->matches('recovery', 'abcde-fghij', $hash));
        self::assertFalse($pepper->matches('recovery', 'wrong-code', $hash));
        self::assertFalse($pepper->matches('otp', 'abcde-fghij', $hash));
    }

    public function testMatchesRejectsMalformedHash(): void
    {
        $pepper = $this->pepper();

        self::assertFalse($pepper->matches('otp', 'value', ''));
        self::assertFalse($pepper->matches('otp', 'value', 'not-hex-zzz'));
    }

    public function testRejectsEmptyApplicationKey(): void
    {
        $this->expectException(InvalidConfigException::class);

        new Pepper('');
    }

    public function testRejectsAnApplicationKeyShorterThan32Bytes(): void
    {
        $this->expectException(InvalidConfigException::class);

        new Pepper('only-31-bytes-0123456789abcdef0');
    }
}
