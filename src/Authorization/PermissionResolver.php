<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Organization;
use Univeros\Polaris\Entity\Permission;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Entity\User;

use function array_keys;

/**
 * Resolves a user's effective authority for an active organization (`docs/auth/rbac.md` §4):
 *
 *     effective(user, org) =
 *         if the user holds the system `superadmin` role → ALL permissions
 *         else  ∪ over the user's roles in that org of each role's permissions
 *
 * Roles (slugs) are the compact default embedded in the access token; the flattened permission
 * `scope` is computed too (used when `access_token.embed_scope` is on, and by the Gate in #36).
 *
 * **Superadmin assignment.** `auth_memberships.organization_id` is NOT NULL, so a user is marked
 * superadmin by a `membership_role` linking any of their memberships to the seeded system
 * `superadmin` role (`organization_id IS NULL`) — the only schema-compatible mechanism, assigned
 * out-of-band by admin tooling. See #35.
 */
final class PermissionResolver
{
    /**
     * @param RepositoryInterface<User>           $users
     * @param RepositoryInterface<Organization>   $organizations
     * @param RepositoryInterface<Membership>     $memberships
     * @param RepositoryInterface<MembershipRole> $membershipRoles
     * @param RepositoryInterface<Role>           $roles
     * @param RepositoryInterface<RolePermission> $rolePermissions
     * @param RepositoryInterface<Permission>     $permissions
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly RepositoryInterface $organizations,
        private readonly RepositoryInterface $memberships,
        private readonly RepositoryInterface $membershipRoles,
        private readonly RepositoryInterface $roles,
        private readonly RepositoryInterface $rolePermissions,
        private readonly RepositoryInterface $permissions,
    ) {
    }

    public function resolve(string $userId, ?string $organizationId): ResolvedAuthority
    {
        // An administratively disabled account has no authority at all, no matter what its
        // not-yet-expired access token claims — the Gate re-resolves here per request, so
        // disabling takes effect immediately (a disabled admin cannot re-enable themselves).
        $user = $this->users->find($userId);
        if ($user instanceof User && $user->status === User::STATUS_DISABLED) {
            return new ResolvedAuthority([], []);
        }

        if ($this->isSuperadmin($userId)) {
            return new ResolvedAuthority([PermissionCatalog::ROLE_SUPERADMIN], $this->allPermissionKeys());
        }

        if ($organizationId === null) {
            return new ResolvedAuthority([], []);
        }

        // A soft-deleted org grants nothing (superadmins, handled above, keep their global
        // override — operators must still be able to inspect a deleted org before purge).
        $organization = $this->organizations->find($organizationId);
        if ($organization instanceof Organization && $organization->status === Organization::STATUS_SUSPENDED) {
            return new ResolvedAuthority([], []);
        }

        $membership = $this->memberships->findOneBy([
            'userId' => $userId,
            'organizationId' => $organizationId,
            'status' => Membership::STATUS_ACTIVE,
        ]);
        if (!$membership instanceof Membership) {
            return new ResolvedAuthority([], []);
        }

        $roleIds = $this->roleIdsOf($membership->id);

        $slugs = [];
        foreach ($roleIds as $roleId) {
            $role = $this->roles->find($roleId);
            if ($role instanceof Role) {
                $slugs[$role->slug] = true;
            }
        }

        $keysById = $this->permissionKeysById();
        $scope = [];
        foreach ($roleIds as $roleId) {
            foreach ($this->rolePermissions->findBy(['roleId' => $roleId]) as $grant) {
                $key = $keysById[$grant->permissionId] ?? null;
                if ($key !== null) {
                    $scope[$key] = true;
                }
            }
        }

        return new ResolvedAuthority(array_keys($slugs), array_keys($scope));
    }

    private function isSuperadmin(string $userId): bool
    {
        $superadminRoleId = $this->superadminRoleId();
        if ($superadminRoleId === null) {
            return false;
        }

        foreach ($this->memberships->findBy(['userId' => $userId]) as $membership) {
            if ($this->membershipRoles->findOneBy(['membershipId' => $membership->id, 'roleId' => $superadminRoleId]) !== null) {
                return true;
            }
        }

        return false;
    }

    private function superadminRoleId(): ?string
    {
        foreach ($this->roles->findBy(['slug' => PermissionCatalog::ROLE_SUPERADMIN]) as $role) {
            if ($role->organizationId === null) {
                return $role->id;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function roleIdsOf(string $membershipId): array
    {
        $roleIds = [];
        foreach ($this->membershipRoles->findBy(['membershipId' => $membershipId]) as $grant) {
            $roleIds[] = $grant->roleId;
        }

        return $roleIds;
    }

    /**
     * @return list<string>
     */
    private function allPermissionKeys(): array
    {
        $keys = [];
        foreach ($this->permissions->findAll() as $permission) {
            $keys[] = $permission->key;
        }

        return $keys;
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
