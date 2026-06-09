<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Permission;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;

/**
 * Verifies the #28 RBAC entities and migrations against a real database driver: the migrations
 * create the expected portable tables, columns, composite primary keys and unique indexes; the
 * attribute-mapped entities round-trip through them; the `ON DELETE CASCADE` foreign keys on the
 * join tables remove grants when a role/permission/membership is deleted; and the migrations roll
 * back cleanly.
 */
final class RolesPermissionsPersistenceTest extends DatabaseTestCase
{
    public function testMigrationsCreateTheTablesWithKeysAndIndexes(): void
    {
        $database = $this->connection();

        self::assertTrue($database->hasTable('auth_roles'));
        self::assertTrue($database->hasTable('auth_permissions'));
        self::assertTrue($database->hasTable('auth_role_permissions'));
        self::assertTrue($database->hasTable('auth_membership_roles'));

        $roles = $database->table('auth_roles');
        foreach (['id', 'organization_id', 'name', 'slug', 'description', 'is_system'] as $column) {
            self::assertTrue($roles->hasColumn($column), "auth_roles.$column should exist");
        }
        self::assertSame(['id'], $roles->getPrimaryKeys());
        self::assertTrue($roles->hasIndex(['organization_id', 'slug']));

        $permissions = $database->table('auth_permissions');
        foreach (['id', 'key', 'description'] as $column) {
            self::assertTrue($permissions->hasColumn($column), "auth_permissions.$column should exist");
        }
        self::assertSame(['id'], $permissions->getPrimaryKeys());
        self::assertTrue($permissions->hasIndex(['key']));

        $rolePermissions = $database->table('auth_role_permissions');
        self::assertSame(['role_id', 'permission_id'], $rolePermissions->getPrimaryKeys());

        $membershipRoles = $database->table('auth_membership_roles');
        self::assertSame(['membership_id', 'role_id'], $membershipRoles->getPrimaryKeys());
    }

    public function testRoleRoundTrips(): void
    {
        $repository = new CycleRepository(Role::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = Uuid::v7()->toRfc4122();
        $role->name = 'Owner';
        $role->slug = 'owner';
        $role->description = 'Full control of the organization';
        $role->isSystem = true;
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $repository->save($role);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['id' => $role->id]);

        self::assertInstanceOf(Role::class, $found);
        self::assertSame($role->organizationId, $found->organizationId);
        self::assertSame('Owner', $found->name);
        self::assertSame('owner', $found->slug);
        self::assertSame('Full control of the organization', $found->description);
        self::assertTrue($found->isSystem);
    }

    public function testSystemRoleAllowsNullOrganization(): void
    {
        $repository = new CycleRepository(Role::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = null;
        $role->name = 'Super Admin';
        $role->slug = 'superadmin';
        $role->isSystem = true;
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $repository->save($role);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['id' => $role->id]);

        self::assertInstanceOf(Role::class, $found);
        self::assertNull($found->organizationId);
        self::assertNull($found->description);
    }

    public function testPermissionRoundTrips(): void
    {
        $repository = new CycleRepository(Permission::class, $this->orm, $this->unitOfWork);

        $permission = new Permission();
        $permission->id = Uuid::v7()->toRfc4122();
        $permission->key = 'test.permission';
        $permission->description = 'A custom, non-catalog permission';
        $repository->save($permission);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['key' => 'test.permission']);

        self::assertInstanceOf(Permission::class, $found);
        self::assertSame('test.permission', $found->key);
        self::assertSame('A custom, non-catalog permission', $found->description);
    }

    public function testRolePermissionGrantRoundTrips(): void
    {
        [$roleId, $permissionId] = $this->seedRoleAndPermission();

        $grants = new CycleRepository(RolePermission::class, $this->orm, $this->unitOfWork);
        $grant = new RolePermission();
        $grant->roleId = $roleId;
        $grant->permissionId = $permissionId;
        $grants->save($grant);

        $this->unitOfWork->clear();

        $found = $grants->findOneBy(['roleId' => $roleId, 'permissionId' => $permissionId]);

        self::assertInstanceOf(RolePermission::class, $found);
        self::assertSame($roleId, $found->roleId);
        self::assertSame($permissionId, $found->permissionId);
    }

    public function testDeletingARoleCascadesItsPermissionGrants(): void
    {
        [$roleId, $permissionId] = $this->seedRoleAndPermission();
        $this->insertRolePermission($roleId, $permissionId);

        $database = $this->connection();
        self::assertSame(1, $database->select()->from('auth_role_permissions')->where('role_id', $roleId)->count());

        $database->delete('auth_roles', ['id' => $roleId])->run();

        self::assertSame(0, $database->select()->from('auth_role_permissions')->where('role_id', $roleId)->count());
        self::assertSame(1, $database->select()->from('auth_permissions')->where('id', $permissionId)->count(), 'The permission itself must remain.');
    }

    public function testDeletingAPermissionCascadesItsRoleGrants(): void
    {
        [$roleId, $permissionId] = $this->seedRoleAndPermission();
        $this->insertRolePermission($roleId, $permissionId);

        $database = $this->connection();
        self::assertSame(1, $database->select()->from('auth_role_permissions')->where('permission_id', $permissionId)->count());

        $database->delete('auth_permissions', ['id' => $permissionId])->run();

        self::assertSame(0, $database->select()->from('auth_role_permissions')->where('permission_id', $permissionId)->count());
        self::assertSame(1, $database->select()->from('auth_roles')->where('id', $roleId)->count(), 'The role itself must remain.');
    }

    public function testDeletingAMembershipCascadesItsRoleGrants(): void
    {
        [$roleId] = $this->seedRoleAndPermission();
        $membershipId = $this->seedMembership();
        $this->insertMembershipRole($membershipId, $roleId);

        $database = $this->connection();
        self::assertSame(1, $database->select()->from('auth_membership_roles')->where('membership_id', $membershipId)->count());

        $database->delete('auth_memberships', ['id' => $membershipId])->run();

        self::assertSame(0, $database->select()->from('auth_membership_roles')->where('membership_id', $membershipId)->count());
        self::assertSame(1, $database->select()->from('auth_roles')->where('id', $roleId)->count(), 'The role itself must remain.');
    }

    public function testDeletingARoleCascadesItsMembershipGrants(): void
    {
        [$roleId] = $this->seedRoleAndPermission();
        $membershipId = $this->seedMembership();
        $this->insertMembershipRole($membershipId, $roleId);

        $database = $this->connection();
        self::assertSame(1, $database->select()->from('auth_membership_roles')->where('role_id', $roleId)->count());

        $database->delete('auth_roles', ['id' => $roleId])->run();

        self::assertSame(0, $database->select()->from('auth_membership_roles')->where('role_id', $roleId)->count());
        self::assertSame(1, $database->select()->from('auth_memberships')->where('id', $membershipId)->count(), 'The membership itself must remain.');
    }

    public function testMigrationsRollBackCleanly(): void
    {
        while ($this->migrator->rollback() !== null) {
            // Roll back every applied migration.
        }

        $database = $this->connection();

        self::assertFalse($database->hasTable('auth_membership_roles'));
        self::assertFalse($database->hasTable('auth_role_permissions'));
        self::assertFalse($database->hasTable('auth_roles'));
        self::assertFalse($database->hasTable('auth_permissions'));
    }

    /**
     * Persists a role and a permission and returns their ids `[roleId, permissionId]`, so join-table
     * inserts have parents to satisfy the foreign keys.
     *
     * @return array{0: string, 1: string}
     */
    private function seedRoleAndPermission(): array
    {
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = Uuid::v7()->toRfc4122();
        $role->name = 'Admin';
        $role->slug = 'admin';
        $role->createdAt = $now;
        $role->updatedAt = $now;
        (new CycleRepository(Role::class, $this->orm, $this->unitOfWork))->save($role);

        $permission = new Permission();
        $permission->id = Uuid::v7()->toRfc4122();
        $permission->key = 'test.grant';
        $permission->description = 'A custom, non-catalog permission';
        (new CycleRepository(Permission::class, $this->orm, $this->unitOfWork))->save($permission);

        $this->unitOfWork->clear();

        return [$role->id, $permission->id];
    }

    private function seedMembership(): string
    {
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = Uuid::v7()->toRfc4122();
        $membership->organizationId = Uuid::v7()->toRfc4122();
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        (new CycleRepository(Membership::class, $this->orm, $this->unitOfWork))->save($membership);

        $this->unitOfWork->clear();

        return $membership->id;
    }

    private function insertRolePermission(string $roleId, string $permissionId): void
    {
        $grant = new RolePermission();
        $grant->roleId = $roleId;
        $grant->permissionId = $permissionId;
        (new CycleRepository(RolePermission::class, $this->orm, $this->unitOfWork))->save($grant);
        $this->unitOfWork->clear();
    }

    private function insertMembershipRole(string $membershipId, string $roleId): void
    {
        $grant = new MembershipRole();
        $grant->membershipId = $membershipId;
        $grant->roleId = $roleId;
        (new CycleRepository(MembershipRole::class, $this->orm, $this->unitOfWork))->save($grant);
        $this->unitOfWork->clear();
    }
}
