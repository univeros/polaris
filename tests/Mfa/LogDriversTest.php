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

        // Record 0 is the construction-time warning that this dev driver writes codes to the log.
        self::assertCount(2, $logger->records);
        self::assertSame('warning', $logger->records[0]['level']);
        self::assertSame('+14155550101', $logger->records[1]['context']['to']);
        self::assertSame('Your code is 123456', $logger->records[1]['context']['message']);
    }

    public function testLogOtpMailerLogsTheRecipientTemplateAndContext(): void
    {
        $logger = new RecordingLogger();

        (new LogOtpMailer($logger))->send('ada@example.com', 'otp_code', ['code' => '123456', 'ttl' => 300]);

        // Record 0 is the construction-time warning that this dev driver writes codes to the log.
        self::assertCount(2, $logger->records);
        self::assertSame('warning', $logger->records[0]['level']);
        self::assertSame('ada@example.com', $logger->records[1]['context']['to']);
        self::assertSame('otp_code', $logger->records[1]['context']['template']);
        self::assertSame(['code' => '123456', 'ttl' => 300], $logger->records[1]['context']['context']);
    }
}
