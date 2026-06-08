<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when an email-verification token is unknown, already consumed, or expired. The
 * endpoint maps this to a generic `400` so it reveals nothing about which condition failed.
 */
final class InvalidVerificationTokenException extends RuntimeException
{
}
