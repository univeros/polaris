<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when inviting an email that already belongs to an active member of the organization.
 * Endpoints map it to `409 conflict`.
 */
final class AlreadyMemberException extends RuntimeException
{
}
