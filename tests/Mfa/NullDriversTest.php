<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Mfa\NullOtpMailer;
use Univeros\Polaris\Mfa\NullSmsSender;

final class NullDriversTest extends TestCase
{
    public function testNullDriversAreSilentNoOps(): void
    {
        (new NullSmsSender())->send('+14155550101', 'ignored');
        (new NullOtpMailer())->send('ada@example.com', 'otp_code', ['code' => '123456']);

        // Nothing is delivered, logged, or thrown.
        $this->expectNotToPerformAssertions();
    }
}
