<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use InvalidArgumentException;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Permission;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\LastOwnerException;
use Univeros\Polaris\Exception\MemberNotFoundException;

use function array_fill_keys;
use function array_keys;
use function in_array;

/**
 * Manages an organization's members: listing them, changing a member's roles, and removing one —
 * enforcing the multi-tenant invariants (`docs/auth/rbac.md` §7) that the permission check alone
 * cannot express:
 *
 * - **No privilege escalation:** an actor may only grant roles whose permissions they themselves
 *   hold (a `superadmin` is exempt).
 * - **Owners are protected from non-owners:** only an owner (or `superadmin`) may modify or remove
 *   an owner.
 * - **Last-owner protection:** an organization must always keep at least one active owner — the last
 *   one cannot be demoted or removed (absolute; even an owner/superadmin cannot orphan the org).
 *
 * The caller's effective authority is re-resolved from the database via {@see PermissionResolver};
 * the token is never trusted for the invariant decisions.
 */
final class MembershipService
{
    /**
     * @param RepositoryInterface<Membership>     $memberships
     * @param RepositoryInterface<MembershipRole> $membershipRoles
     * @param RepositoryInterface<Role>           $roles
     * @param RepositoryInterface<RolePermission> $rolePermissions
     * @param RepositoryInterface<Permission>     $permissions
     * @param RepositoryInterface<User>           $users
     */
    public function __construct(
        private readonly RepositoryInterface $memberships,
        private readonly RepositoryInterface $membershipRoles,
        private readonly RepositoryInterface $roles,
        private readonly RepositoryInterface $rolePermissions,
        private readonly RepositoryInterface $permissions,
        private readonly RepositoryInterface $users,
        private readonly PermissionResolver $resolver,
        private readonly UnitOfWorkInterface $unitOfWork,
    ) {
    }

    /**
     * @return list<array<string, mixed>> each member: user_id, email, display_name, status, roles
     */
    public function listMembers(string $organizationId): array
    {
        $members = [];
        foreach ($this->memberships->findBy(['organizationId' => $organizationId]) as $membership) {
            $user = $this->users->find($membership->userId);
            $members[] = [
                'user_id' => $membership->userId,
                'email' => $user instanceof User ? $user->email : null,
                'display_name' => $user instanceof User ? $user->displayName : null,
                'status' => $membership->status,
                'roles' => $this->roleSlugsOf($membership->id),
            ];
        }

        return $members;
    }

    /**
     * Replace a member's roles with the given slugs.
     *
     * @param list<string> $roleSlugs
     *
     * @throws MemberNotFoundException  the target is not a member of the org
     * @throws InvalidArgumentException an unknown role slug for the org
     * @throws AuthorizationException   escalation, or a non-owner modifying an owner
     * @throws LastOwnerException       demoting the last owner
     */
    public function changeRoles(string $actorUserId, string $organizationId, string $targetUserId, array $roleSlugs): void
    {
        $target = $this->memberOrFail($organizationId, $targetUserId);

        // Resolve each requested slug to one of this org's roles.
        $newRoleIds = [];
        foreach ($roleSlugs as $slug) {
            $role = $this->roles->findOneBy(['organizationId' => $organizationId, 'slug' => $slug]);
            if (!$role instanceof Role) {
                throw new InvalidArgumentException("Unknown role for this organization: $slug");
            }
            $newRoleIds[$role->id] = true;
        }

        $actor = $this->resolver->resolve($actorUserId, $organizationId);
        $targetWasOwner = in_array(PermissionCatalog::ROLE_OWNER, $this->roleSlugsOf($target->id), true);

        if (!$this->isSuperadmin($actor)) {
            if ($targetWasOwner && !$this->isOwner($actor)) {
                throw new AuthorizationException('Only an owner can modify an owner.');
            }
            $this->assertNoEscalation($actor, array_keys($newRoleIds));
        }

        $keepsOwner = isset($newRoleIds[$this->ownerRoleId($organizationId) ?? '']);
        if ($targetWasOwner && !$keepsOwner && $this->activeOwnerCount($organizationId) <= 1) {
            throw new LastOwnerException('The organization must keep at least one owner.');
        }

        foreach ($this->membershipRoles->findBy(['membershipId' => $target->id]) as $existing) {
            $this->unitOfWork->remove($existing);
        }
        foreach (array_keys($newRoleIds) as $roleId) {
            $link = new MembershipRole();
            $link->membershipId = $target->id;
            $link->roleId = $roleId;
            $this->unitOfWork->persist($link);
        }
        $this->unitOfWork->flush();
    }

    /**
     * Remove a member from the organization.
     *
     * @throws MemberNotFoundException the target is not a member of the org
     * @throws AuthorizationException  a non-owner removing an owner
     * @throws LastOwnerException      removing the last owner
     */
    public function removeMember(string $actorUserId, string $organizationId, string $targetUserId): void
    {
        $target = $this->memberOrFail($organizationId, $targetUserId);

        $actor = $this->resolver->resolve($actorUserId, $organizationId);
        $targetIsOwner = in_array(PermissionCatalog::ROLE_OWNER, $this->roleSlugsOf($target->id), true);

        if (!$this->isSuperadmin($actor) && $targetIsOwner && !$this->isOwner($actor)) {
            throw new AuthorizationException('Only an owner can remove an owner.');
        }

        if ($targetIsOwner && $this->activeOwnerCount($organizationId) <= 1) {
            throw new LastOwnerException('The organization must keep at least one owner.');
        }

        // The auth_membership_roles rows cascade away with the membership (FK ON DELETE CASCADE).
        $this->unitOfWork->remove($target);
        $this->unitOfWork->flush();
    }

    private function memberOrFail(string $organizationId, string $userId): Membership
    {
        $membership = $this->memberships->findOneBy(['userId' => $userId, 'organizationId' => $organizationId]);
        if (!$membership instanceof Membership) {
            throw new MemberNotFoundException('The user is not a member of this organization.');
        }

        return $membership;
    }

    /**
     * @param list<string> $newRoleIds
     *
     * @throws AuthorizationException when a requested role grants a permission the actor lacks
     */
    private function assertNoEscalation(ResolvedAuthority $actor, array $newRoleIds): void
    {
        $held = array_fill_keys($actor->scope, true);
        $keysById = $this->permissionKeysById();

        foreach ($newRoleIds as $roleId) {
            foreach ($this->rolePermissions->findBy(['roleId' => $roleId]) as $grant) {
                $key = $keysById[$grant->permissionId] ?? null;
                if ($key !== null && !isset($held[$key])) {
                    throw new AuthorizationException('You cannot grant permissions you do not hold.');
                }
            }
        }
    }

    /**
     * @return list<string>
     */
    private function roleSlugsOf(string $membershipId): array
    {
        $slugs = [];
        foreach ($this->membershipRoles->findBy(['membershipId' => $membershipId]) as $link) {
            $role = $this->roles->find($link->roleId);
            if ($role instanceof Role) {
                $slugs[] = $role->slug;
            }
        }

        return $slugs;
    }

    private function activeOwnerCount(string $organizationId): int
    {
        $ownerRoleId = $this->ownerRoleId($organizationId);
        if ($ownerRoleId === null) {
            return 0;
        }

        $count = 0;
        foreach ($this->membershipRoles->findBy(['roleId' => $ownerRoleId]) as $link) {
            $membership = $this->memberships->find($link->membershipId);
            if ($membership instanceof Membership && $membership->status === Membership::STATUS_ACTIVE) {
                $count++;
            }
        }

        return $count;
    }

    private function ownerRoleId(string $organizationId): ?string
    {
        $role = $this->roles->findOneBy(['organizationId' => $organizationId, 'slug' => PermissionCatalog::ROLE_OWNER]);

        return $role instanceof Role ? $role->id : null;
    }

    private function isSuperadmin(ResolvedAuthority $authority): bool
    {
        return in_array(PermissionCatalog::ROLE_SUPERADMIN, $authority->roles, true);
    }

    private function isOwner(ResolvedAuthority $authority): bool
    {
        return in_array(PermissionCatalog::ROLE_OWNER, $authority->roles, true);
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
