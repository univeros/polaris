<?php

declare(strict_types=1);

namespace Univeros\Polaris\Security;

use Override;
use SensitiveParameter;
use Univeros\Polaris\Contracts\BreachedPasswordCheckInterface;

/**
 * The default no-op breach check: nothing is ever considered breached. Bound when the host has
 * not provided an adapter (or has the check disabled), keeping the password policy dependency
 * graph simple.
 */
final class NullBreachedPasswordCheck implements BreachedPasswordCheckInterface
{
    #[Override]
    public function isBreached(#[SensitiveParameter] string $password): bool
    {
        return false;
    }
}
