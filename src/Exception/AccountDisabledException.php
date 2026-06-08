<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when the credentials are correct but the account has been disabled (an admin
 * action). Surfaced as a `403` — revealed only to someone who already proved the password,
 * so it is not an enumeration signal.
 */
final class AccountDisabledException extends RuntimeException
{
}
