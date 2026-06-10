<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use SensitiveParameter;
use Univeros\Polaris\Contracts\BreachedPasswordCheckInterface;

use function mb_strlen;
use function sprintf;

/**
 * Enforces the password policy before hashing: the minimum-length rule (from
 * {@see \Univeros\Polaris\Config\AuthConfig}) and, when an adapter is wired
 * (`auth.password.breach_check`), the breached-password screen behind
 * {@see BreachedPasswordCheckInterface}. Returns the list of failed rules (empty = valid) so
 * callers can surface them as a `422`.
 */
final readonly class PasswordPolicy
{
    public function __construct(
        private int $minLength,
        private ?BreachedPasswordCheckInterface $breaches = null,
    ) {
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

        if ($this->breaches !== null && $this->breaches->isBreached($password)) {
            $violations[] = 'This password has appeared in a known data breach; choose a different one.';
        }

        return $violations;
    }
}
