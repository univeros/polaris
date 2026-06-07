<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown at boot when Polaris configuration or required secrets are missing or invalid.
 *
 * Polaris fails fast: a host that registers the module without a valid configuration
 * and the required environment secrets gets a clear startup error rather than an
 * insecure default.
 */
final class InvalidConfigException extends RuntimeException
{
}
