<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a submitted OTP/TOTP code is wrong, expired, or a replay of an already-consumed
 * step. The endpoint maps this to a generic `422`, revealing nothing about which condition failed.
 */
final class InvalidOtpException extends RuntimeException
{
}
