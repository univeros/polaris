<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Configuration\Support\Env;

/**
 * An environment the test describes in full. The framework's {@see Env} reads `$_ENV`, `$_SERVER`
 * and `getenv()`, so a variable exported to the process (CI exports `DB_*`) would leak into a test
 * that `putenv()` can neither clear nor override.
 */
final class ArrayEnv extends Env
{
    /**
     * @param array<string, string> $values
     */
    public function __construct(private readonly array $values)
    {
    }

    public function get($name, mixed $default = null): mixed
    {
        return $this->values[$name] ?? $default;
    }
}
