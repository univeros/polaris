<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Mfa\EndroidQrRenderer;

use function str_contains;

final class EndroidQrRendererTest extends TestCase
{
    public function testRendersDataAsAnSvgDocument(): void
    {
        $svg = (new EndroidQrRenderer())->svg('otpauth://totp/Univeros:ada@example.com?secret=ABC&issuer=Univeros');

        self::assertNotSame('', $svg);
        self::assertTrue(str_contains($svg, '<svg'), 'output is SVG markup');
    }
}
