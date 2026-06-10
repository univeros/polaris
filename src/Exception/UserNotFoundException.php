<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a users-admin operation targets a user id that does not exist. Endpoints map it to
 * `404 not_found`.
 */
final class UserNotFoundException extends RuntimeException
{
}
