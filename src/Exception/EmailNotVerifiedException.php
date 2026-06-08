<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when the credentials are correct but the email is unverified and the host
 * requires verification before login (`flows.require_verified_email`). Surfaced as a
 * `403 email_unverified` with a resend hint — actionable and only shown post-authentication.
 */
final class EmailNotVerifiedException extends RuntimeException
{
}
