<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a login fails for a credential or lock reason — unknown user, wrong
 * password, or a locked account. The endpoint maps every case to an identical generic
 * `401` so it never reveals which account exists or why it failed (anti-enumeration).
 */
final class InvalidCredentialsException extends RuntimeException
{
}
