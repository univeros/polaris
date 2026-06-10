<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Univeros\Polaris\Entity\Permission;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Exception\AuthorizationException;

use function array_fill_keys;
use function in_array;

/**
 * The no-privilege-escalation invariant (`docs/auth/rbac.md` §7), shared by role changes and
 * invitations: an actor may only grant roles whose permissions they themselves hold. A
 * `superadmin` is exempt.
 */
final class EscalationGuard
{
    /**
     * @param RepositoryInterface<RolePermission> $rolePermissions
     * @param RepositoryInterface<Permission>     $permissions
     */
    public function __construct(
        private readonly RepositoryInterface $rolePermissions,
        private readonly RepositoryInterface $permissions,
    ) {
    }

    /**
     * @param list<string> $roleIds the roles the actor wants to grant
     *
     * @throws AuthorizationException when a role grants a permission the actor lacks
     */
    public function assertCanGrant(ResolvedAuthority $actor, array $roleIds): void
    {
        if (in_array(PermissionCatalog::ROLE_SUPERADMIN, $actor->roles, true)) {
            return;
        }

        $held = array_fill_keys($actor->scope, true);
        $keysById = $this->permissionKeysById();

        foreach ($roleIds as $roleId) {
            foreach ($this->rolePermissions->findBy(['roleId' => $roleId]) as $grant) {
                $key = $keysById[$grant->permissionId] ?? null;
                if ($key !== null && !isset($held[$key])) {
                    throw new AuthorizationException('You cannot grant permissions you do not hold.');
                }
            }
        }
    }

    /**
     * Same invariant, key-level: an actor may only put permissions they themselves hold into a
     * role (creating or editing one) — otherwise editing a role you are assigned is instant
     * self-escalation. A `superadmin` is exempt.
     *
     * @param list<string> $permissionKeys
     *
     * @throws AuthorizationException when a key is outside the actor's own authority
     */
    public function assertCanGrantPermissionKeys(ResolvedAuthority $actor, array $permissionKeys): void
    {
        if (in_array(PermissionCatalog::ROLE_SUPERADMIN, $actor->roles, true)) {
            return;
        }

        $held = array_fill_keys($actor->scope, true);
        foreach ($permissionKeys as $key) {
            if (!isset($held[$key])) {
                throw new AuthorizationException('You cannot grant permissions you do not hold.');
            }
        }
    }

    /**
     * @return array<string, string> permission id => key
     */
    private function permissionKeysById(): array
    {
        $map = [];
        foreach ($this->permissions->findAll() as $permission) {
            $map[$permission->id] = $permission->key;
        }

        return $map;
    }
}
