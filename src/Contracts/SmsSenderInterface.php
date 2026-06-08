<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

/**
 * Delivers an SMS (typically a one-time code) to a phone number.
 *
 * A port so Polaris stays provider-agnostic and dependency-light: core ships dev drivers
 * ({@see \Univeros\Polaris\Mfa\LogSmsSender}, {@see \Univeros\Polaris\Mfa\NullSmsSender}); a
 * host binds a production adapter (Twilio/SNS/…) in its container.
 */
interface SmsSenderInterface
{
    /**
     * @param non-empty-string $toE164 destination phone in E.164 form, e.g. `+14155550101`
     */
    public function send(string $toE164, string $message): void;
}
