<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\Permission;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\RoleNotFoundException;
use Univeros\Polaris\Exception\RoleSlugConflictException;

use function array_fill_keys;
use function array_flip;
use function array_keys;
use function in_array;
use function preg_match;
use function trim;

/**
 * Per-organization roles management and the global permission catalog (`docs/auth/rbac.md` §8).
 *
 * Only the org's own roles are reachable — an unknown id, another org's role, and a global system
 * role all read as not-found. Two role classes are immutable to tenants: rows flagged
 * {@see Role::$isSystem}, and the org's cloned `owner` role, which anchors the last-owner and
 * owner-protection invariants in {@see MembershipService}. A role's permission keys are
 * constrained to the actor's own authority ({@see EscalationGuard::assertCanGrantPermissionKeys()})
 * — editing a role you are assigned must not be a self-escalation path — and to keys that exist
 * in the catalog. Deleting a role detaches it everywhere via `ON DELETE CASCADE`.
 */
final class RoleService
{
    private const string SLUG_PATTERN = '/^[a-z0-9][a-z0-9-]{0,79}$/';

    /**
     * @param RepositoryInterface<Role>           $roles
     * @param RepositoryInterface<RolePermission> $rolePermissions
     * @param RepositoryInterface<Permission>     $permissions
     */
    public function __construct(
        private readonly RepositoryInterface $roles,
        private readonly RepositoryInterface $rolePermissions,
        private readonly RepositoryInterface $permissions,
        private readonly PermissionResolver $resolver,
        private readonly EscalationGuard $escalation,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The organization's roles with their permission keys.
     *
     * @return list<array<string, mixed>>
     */
    public function listRoles(string $organizationId): array
    {
        $keysById = $this->permissionKeysById();

        $list = [];
        foreach ($this->roles->findBy(['organizationId' => $organizationId]) as $role) {
            $list[] = $this->shape($role, $keysById);
        }

        return $list;
    }

    /**
     * Create a custom role.
     *
     * @param list<string> $permissionKeys
     *
     * @return array<string, mixed> the created role: id, name, slug, description, is_system, permission_keys
     *
     * @throws InvalidArgumentException  empty name, malformed slug, or an unknown permission key
     * @throws RoleSlugConflictException the slug is already used in the org
     * @throws AuthorizationException    a key outside the actor's own authority
     */
    public function create(
        string $actorUserId,
        string $organizationId,
        string $name,
        string $slug,
        ?string $description,
        array $permissionKeys,
    ): array {
        $name = trim($name);
        if ($name === '') {
            throw new InvalidArgumentException('A role name is required.');
        }
        if (preg_match(self::SLUG_PATTERN, $slug) !== 1) {
            throw new InvalidArgumentException('The slug must be lowercase letters, digits and hyphens.');
        }
        if ($this->roles->findOneBy(['organizationId' => $organizationId, 'slug' => $slug]) instanceof Role) {
            throw new RoleSlugConflictException($slug);
        }

        $idsByKey = $this->permissionIdsByKey();
        $permissionIds = $this->permissionIdsFor($permissionKeys, $idsByKey);
        $this->escalation->assertCanGrantPermissionKeys($this->resolver->resolve($actorUserId, $organizationId), $permissionKeys);

        $now = $this->clock->now();
        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = $organizationId;
        $role->name = $name;
        $role->slug = $slug;
        $role->description = $description;
        $role->isSystem = false;
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $this->unitOfWork->persist($role);

        foreach ($permissionIds as $permissionId) {
            $grant = new RolePermission();
            $grant->roleId = $role->id;
            $grant->permissionId = $permissionId;
            $this->unitOfWork->persist($grant);
        }
        $this->unitOfWork->flush();

        return $this->shape($role, array_flip($idsByKey));
    }

    /**
     * Update a role's name, description, and/or permission set (the slug is immutable).
     *
     * @param list<string>|null $permissionKeys null leaves the permission set untouched
     *
     * @return array<string, mixed> the updated role
     *
     * @throws RoleNotFoundException    unknown id, another org's role, or a global system role
     * @throws AuthorizationException   an immutable role, or a key outside the actor's authority
     * @throws InvalidArgumentException an unknown permission key or empty name
     */
    public function update(
        string $actorUserId,
        string $organizationId,
        string $roleId,
        ?string $name,
        ?string $description,
        ?array $permissionKeys,
    ): array {
        $role = $this->orgRoleOrFail($organizationId, $roleId);
        $this->assertMutable($role);

        if ($name !== null) {
            $name = trim($name);
            if ($name === '') {
                throw new InvalidArgumentException('A role name is required.');
            }
            $role->name = $name;
        }
        if ($description !== null) {
            $role->description = $description;
        }

        if ($permissionKeys !== null) {
            $permissionIds = $this->permissionIdsFor($permissionKeys, $this->permissionIdsByKey());
            $this->escalation->assertCanGrantPermissionKeys(
                $this->resolver->resolve($actorUserId, $organizationId),
                $permissionKeys,
            );

            // Diff rather than wipe-and-reinsert: the unit of work runs inserts before deletes,
            // so re-adding a kept grant would violate the composite primary key.
            $wanted = array_fill_keys($permissionIds, true);
            foreach ($this->rolePermissions->findBy(['roleId' => $role->id]) as $existing) {
                if (isset($wanted[$existing->permissionId])) {
                    unset($wanted[$existing->permissionId]);
                } else {
                    $this->unitOfWork->remove($existing);
                }
            }
            foreach (array_keys($wanted) as $permissionId) {
                $grant = new RolePermission();
                $grant->roleId = $role->id;
                $grant->permissionId = $permissionId;
                $this->unitOfWork->persist($grant);
            }
        }

        $role->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($role);
        $this->unitOfWork->flush();

        return $this->shape($role, $this->permissionKeysById());
    }

    /**
     * Delete a role; the DB cascade detaches it from all memberships and drops its grants.
     *
     * @throws RoleNotFoundException  unknown id, another org's role, or a global system role
     * @throws AuthorizationException an immutable role, or a cloned template (owner/admin/member)
     */
    public function delete(string $organizationId, string $roleId): void
    {
        $role = $this->orgRoleOrFail($organizationId, $roleId);
        $this->assertMutable($role);
        // The cloned templates stay editable (tenant-owned), but deleting them would
        // cascade-strip members and break every flow that assigns by template slug.
        if (in_array($role->slug, [PermissionCatalog::ROLE_ADMIN, PermissionCatalog::ROLE_MEMBER], true)) {
            throw new AuthorizationException("The {$role->slug} role cannot be deleted.");
        }

        $this->unitOfWork->remove($role);
        $this->unitOfWork->flush();
    }

    /**
     * The full permission catalog (Polaris core ∪ host-contributed), for building role UIs.
     *
     * @return list<array{key: string, description: string}>
     */
    public function permissionCatalog(): array
    {
        $catalog = [];
        foreach ($this->permissions->findAll() as $permission) {
            $catalog[] = ['key' => $permission->key, 'description' => $permission->description];
        }

        return $catalog;
    }

    private function orgRoleOrFail(string $organizationId, string $roleId): Role
    {
        $role = $this->roles->find($roleId);
        if (!$role instanceof Role || $role->organizationId !== $organizationId) {
            throw new RoleNotFoundException('The role does not exist in this organization.');
        }

        return $role;
    }

    /**
     * @throws AuthorizationException for roles tenants must not change
     */
    private function assertMutable(Role $role): void
    {
        if ($role->isSystem) {
            throw new AuthorizationException('System roles cannot be modified.');
        }
        // The owner role anchors the last-owner / owner-protection invariants; editing or
        // deleting it could orphan the organization.
        if ($role->slug === PermissionCatalog::ROLE_OWNER) {
            throw new AuthorizationException('The owner role cannot be modified.');
        }
    }

    /**
     * Resolve catalog keys to permission ids, rejecting unknown keys.
     *
     * @param list<string>          $permissionKeys
     * @param array<string, string> $idsByKey       permission key => id
     *
     * @return list<string>
     *
     * @throws InvalidArgumentException
     */
    private function permissionIdsFor(array $permissionKeys, array $idsByKey): array
    {
        $ids = [];
        foreach ($permissionKeys as $key) {
            $id = $idsByKey[$key] ?? null;
            if ($id === null) {
                throw new InvalidArgumentException("Unknown permission key: $key");
            }
            $ids[] = $id;
        }

        return $ids;
    }

    /**
     * @return array<string, string> permission key => id
     */
    private function permissionIdsByKey(): array
    {
        $map = [];
        foreach ($this->permissions->findAll() as $permission) {
            $map[$permission->key] = $permission->id;
        }

        return $map;
    }

    /**
     * @param array<string, string> $keysById permission id => key
     *
     * @return array<string, mixed>
     */
    private function shape(Role $role, array $keysById): array
    {
        $keys = [];
        foreach ($this->rolePermissions->findBy(['roleId' => $role->id]) as $grant) {
            $key = $keysById[$grant->permissionId] ?? null;
            if ($key !== null) {
                $keys[] = $key;
            }
        }

        return [
            'id' => $role->id,
            'name' => $role->name,
            'slug' => $role->slug,
            'description' => $role->description,
            'is_system' => $role->isSystem,
            'permission_keys' => $keys,
        ];
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
