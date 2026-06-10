<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a roles operation targets a role that does not exist in the organization — an
 * unknown id, another org's role, and a global system role are deliberately indistinguishable.
 * Endpoints map it to `404 not_found`.
 */
final class RoleNotFoundException extends RuntimeException
{
}
