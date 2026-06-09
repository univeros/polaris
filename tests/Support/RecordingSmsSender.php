<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Univeros\Polaris\Contracts\SmsSenderInterface;

/**
 * An {@see SmsSenderInterface} that records what it was asked to send, so a test can assert the
 * destination and message (and recover the OTP code from the message).
 */
final class RecordingSmsSender implements SmsSenderInterface
{
    /** @var list<array{to: string, message: string}> */
    public array $sent = [];

    #[Override]
    public function send(string $toE164, string $message): void
    {
        $this->sent[] = ['to' => $toE164, 'message' => $message];
    }
}
