<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Override;
use Psr\Log\LoggerInterface;
use Univeros\Polaris\Contracts\OtpMailerInterface;

/**
 * Dev/test email driver: instead of sending, it writes the recipient, template, and context
 * (which carries the OTP code) to the PSR-3 logger so a developer can complete a flow without a
 * mail provider.
 *
 * The default {@see OtpMailerInterface} binding until a host wires a production adapter
 * (SES/SMTP/…). **Not for production** — it neither delivers nor redacts the code.
 */
final readonly class LogOtpMailer implements OtpMailerInterface
{
    public function __construct(private LoggerInterface $logger)
    {
        // A WARNING at construction makes a forgotten production binding loud in any log
        // aggregator: this driver writes live one-time codes to the log instead of delivering.
        $this->logger->warning(
            'Polaris is using the development Log email driver; one-time codes will be WRITTEN TO THE LOG, not delivered. Bind a production adapter before going live.',
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
        $this->logger->info('Polaris dev email (not delivered)', [
            'to' => $toEmail,
            'template' => $template,
            'context' => $context,
        ]);
    }
}
