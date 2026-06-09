<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Univeros\Polaris\Contracts\OtpMailerInterface;

/**
 * An {@see OtpMailerInterface} that records what it was asked to send, so a test can assert the
 * recipient, template, and context (which carries the OTP code).
 */
final class RecordingOtpMailer implements OtpMailerInterface
{
    /** @var list<array{to: string, template: string, context: array<string, mixed>}> */
    public array $sent = [];

    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
        $this->sent[] = ['to' => $toEmail, 'template' => $template, 'context' => $context];
    }
}
