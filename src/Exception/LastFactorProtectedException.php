<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when removing an MFA factor would leave a user for whom MFA is enforced with no confirmed
 * factor at all (spec §8). The endpoint maps this to `409` — the user must enrol a replacement
 * factor before removing their last one.
 */
final class LastFactorProtectedException extends RuntimeException
{
}
