<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

use SensitiveParameter;

/**
 * Port for breached-password screening (`docs/auth/security.md`): tells whether a candidate
 * password is known from public credential dumps. Polaris ships an HIBP k-anonymity adapter
 * ({@see \Univeros\Polaris\Security\HibpBreachedPasswordCheck}); hosts may bind their own.
 *
 * Implementations must be **fail-open**: when the upstream source is unreachable, return false
 * rather than blocking sign-ups on a third-party outage.
 */
interface BreachedPasswordCheckInterface
{
    public function isBreached(#[SensitiveParameter] string $password): bool;
}
