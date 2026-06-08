<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a password-reset token is unknown, already consumed, or expired. The
 * endpoint maps this to a generic `400`, revealing nothing about which condition failed.
 */
final class InvalidResetTokenException extends RuntimeException
{
}
