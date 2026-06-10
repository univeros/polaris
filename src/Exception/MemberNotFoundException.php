<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a membership operation targets a user who is not a member of the organization.
 * Endpoints map it to `404 not_found`.
 */
final class MemberNotFoundException extends RuntimeException
{
}
