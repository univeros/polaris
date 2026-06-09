<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when an MFA factor management operation is invalid for the factor's current state — for
 * example, making an **unconfirmed** factor the default (only a confirmed factor can satisfy MFA, so
 * only a confirmed factor may be the default). The endpoint maps this to `422`.
 */
final class InvalidMfaFactorStateException extends RuntimeException
{
}
