<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when an MFA factor does not exist or does not belong to the caller. The endpoint maps
 * this to `404` — a factor owned by another user is indistinguishable from one that never existed.
 */
final class MfaFactorNotFoundException extends RuntimeException
{
}
