<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a new OTP code is requested before the resend cooldown (`auth.otp.resend_cooldown`)
 * has elapsed. The endpoint maps this to `429`, throttling SMS/email cost and OTP-bombing.
 */
final class OtpCooldownException extends RuntimeException
{
}
