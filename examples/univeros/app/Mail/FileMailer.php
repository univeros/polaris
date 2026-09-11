<?php

declare(strict_types=1);

namespace App\Mail;

use Override;
use Polaris\Contract\OtpMailerInterface;

use function file_put_contents;
use function json_encode;

use const FILE_APPEND;
use const JSON_THROW_ON_ERROR;

/**
 * The demo mailbox: every email Polaris would send becomes one JSON line in var/mail.log, so
 * bin/walkthrough.sh can read verification tokens and one-time codes from it.
 */
final class FileMailer implements OtpMailerInterface
{
    public function __construct(private readonly string $file)
    {
    }

    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
        file_put_contents(
            $this->file,
            json_encode(['to' => $toEmail, 'template' => $template, 'context' => $context], JSON_THROW_ON_ERROR) . "\n",
            FILE_APPEND,
        );
    }
}
