<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Override;
use Psr\Log\LoggerInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;

/**
 * Dev/test SMS driver: instead of sending, it writes the message to the PSR-3 logger so a
 * developer can read the OTP from the logs and complete a flow without a real provider.
 *
 * The default {@see SmsSenderInterface} binding until a host wires a production adapter
 * (Twilio/SNS/…). **Not for production** — it neither delivers nor redacts the code.
 */
final readonly class LogSmsSender implements SmsSenderInterface
{
    public function __construct(private LoggerInterface $logger)
    {
        // A WARNING at construction makes a forgotten production binding loud in any log
        // aggregator: this driver writes live one-time codes to the log instead of delivering.
        $this->logger->warning(
            'Polaris is using the development Log SMS driver; one-time codes will be WRITTEN TO THE LOG, not delivered. Bind a production adapter before going live.',
        );
    }

    #[Override]
    public function send(string $toE164, string $message): void
    {
        $this->logger->info('Polaris dev SMS (not delivered)', ['to' => $toE164, 'message' => $message]);
    }
}
