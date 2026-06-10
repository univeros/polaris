<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when an invitation operation targets an invitation that does not exist (or belongs to a
 * different organization). Endpoints map it to `404 not_found`.
 */
final class InvitationNotFoundException extends RuntimeException
{
}
