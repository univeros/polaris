<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Mfa\LogOtpMailer;
use Univeros\Polaris\Mfa\LogSmsSender;
use Univeros\Polaris\Tests\Support\RecordingLogger;

final class LogDriversTest extends TestCase
{
    public function testLogSmsSenderLogsTheRecipientAndMessage(): void
    {
        $logger = new RecordingLogger();

        (new LogSmsSender($logger))->send('+14155550101', 'Your code is 123456');

        self::assertCount(1, $logger->records);
        self::assertSame('+14155550101', $logger->records[0]['context']['to']);
        self::assertSame('Your code is 123456', $logger->records[0]['context']['message']);
    }

    public function testLogOtpMailerLogsTheRecipientTemplateAndContext(): void
    {
        $logger = new RecordingLogger();

        (new LogOtpMailer($logger))->send('ada@example.com', 'otp_code', ['code' => '123456', 'ttl' => 300]);

        self::assertCount(1, $logger->records);
        self::assertSame('ada@example.com', $logger->records[0]['context']['to']);
        self::assertSame('otp_code', $logger->records[0]['context']['template']);
        self::assertSame(['code' => '123456', 'ttl' => 300], $logger->records[0]['context']['context']);
    }
}
