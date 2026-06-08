<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

/**
 * Delivers a transactional OTP/notification email.
 *
 * A port so Polaris stays provider-agnostic: core ships dev drivers
 * ({@see \Univeros\Polaris\Mfa\LogOtpMailer}, {@see \Univeros\Polaris\Mfa\NullOtpMailer}); a
 * host binds a production adapter (SES/SMTP/…) that renders `$template` with `$context`.
 */
interface OtpMailerInterface
{
    /**
     * @param string               $template a logical template name (e.g. `otp_code`) the adapter renders
     * @param array<string, mixed> $context  template variables (code, ttl, app name, …)
     */
    public function send(string $toEmail, string $template, array $context): void;
}
