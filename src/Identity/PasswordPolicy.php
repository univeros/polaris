<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use SensitiveParameter;

use function mb_strlen;
use function sprintf;

/**
 * Enforces the password policy before hashing. Currently the minimum-length rule (from
 * {@see \Univeros\Polaris\Config\AuthConfig}); the breached-password check is layered in
 * a later phase behind its own port. Returns the list of failed rules (empty = valid) so
 * callers can surface them as a `422`.
 */
final readonly class PasswordPolicy
{
    public function __construct(private int $minLength)
    {
    }

    /**
     * @return list<string>
     */
    public function validate(#[SensitiveParameter] string $password): array
    {
        $violations = [];

        if (mb_strlen($password) < $this->minLength) {
            $violations[] = sprintf('Password must be at least %d characters long.', $this->minLength);
        }

        return $violations;
    }
}
