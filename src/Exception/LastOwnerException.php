<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when an operation would leave an organization with no owner — removing or demoting its
 * last owner. An organization must always retain at least one owner. Endpoints map it to
 * `409 conflict`.
 */
final class LastOwnerException extends RuntimeException
{
}
