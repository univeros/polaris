<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a presented refresh token cannot be exchanged: it is unknown, expired, or
 * otherwise not a valid grant. The refresh endpoint maps this to a `401 invalid_grant`
 * with a generic message (no detail that would help an attacker probe token state).
 */
class InvalidGrantException extends RuntimeException
{
}
