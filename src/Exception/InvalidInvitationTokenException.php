<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when an invite token presented to the accept endpoint is unknown, already consumed,
 * revoked, or expired. Endpoints map it to `400` without revealing which condition failed.
 */
final class InvalidInvitationTokenException extends RuntimeException
{
}
