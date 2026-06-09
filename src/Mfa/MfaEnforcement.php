<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\User;

/**
 * Decides whether MFA is **enforced** for a user (spec §8): the global `auth.mfa.enforce` switch, or
 * the per-user `mfa_enforced` flag. (Per-organisation policy arrives with the RBAC phase; there is no
 * org entity yet.)
 *
 * Enforcement is what makes the last confirmed factor undeletable ({@see MfaManagementService}) and,
 * in a later step, drives grace-enrollment.
 */
final readonly class MfaEnforcement
{
    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(
        private RepositoryInterface $users,
        private AuthConfig $config,
    ) {
    }

    public function isEnforced(string $userId): bool
    {
        if ($this->config->mfaEnforce) {
            return true;
        }

        $user = $this->users->find($userId);

        return $user instanceof User && $user->mfaEnforced;
    }
}
