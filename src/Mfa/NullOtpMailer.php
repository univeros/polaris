<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Override;
use Univeros\Polaris\Contracts\OtpMailerInterface;

/**
 * A no-op email driver for environments that disable the email OTP channel entirely (it neither
 * sends nor logs). Bind this as {@see OtpMailerInterface} to silently drop email delivery.
 */
final class NullOtpMailer implements OtpMailerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
    }
}
