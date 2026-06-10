<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Persistence\MembershipRepository;
use Univeros\Polaris\Persistence\MembershipRoleRepository;
use Univeros\Polaris\Persistence\PermissionRepository;
use Univeros\Polaris\Persistence\RolePermissionRepository;
use Univeros\Polaris\Persistence\RoleRepository;

use function is_array;
use function is_string;

/**
 * Verifies the #35 {@see PermissionResolver} against a real driver: a member's effective authority
 * is the union of their roles' permissions for the active org; a non-member or no-active-org
 * resolves empty; and a user holding the system `superadmin` role resolves to every permission.
 * The permission catalog + system roles are seeded by the base {@see DatabaseTestCase}.
 */
final class PermissionResolverTest extends DatabaseTestCase
{
    private const string ORG = '01910000-0000-7000-8000-0000000000aa';

    public function testResolvesARolesSlugAndPermissions(): void
    {
        $userId = $this->member(self::ORG);
        $role = $this->orgRole(self::ORG, 'owner');
        $this->grant($role, 'org.read');
        $this->grant($role, 'members.read');
        $this->assign($userId, self::ORG, $role);

        $authority = $this->resolver()->resolve($userId, self::ORG);

        self::assertSame(['owner'], $authority->roles);
        self::assertEqualsCanonicalizing(['org.read', 'members.read'], $authority->scope);
    }

    public function testResolvesTheUnionOfMultipleRoles(): void
    {
        $userId = $this->member(self::ORG);
        $owner = $this->orgRole(self::ORG, 'owner');
        $this->grant($owner, 'org.read');
        $this->grant($owner, 'members.read');
        $member = $this->orgRole(self::ORG, 'member');
        $this->grant($member, 'org.read'); // overlaps — must dedupe
        $this->grant($member, 'roles.read');
        $this->assign($userId, self::ORG, $owner);
        $this->assign($userId, self::ORG, $member);

        $authority = $this->resolver()->resolve($userId, self::ORG);

        self::assertEqualsCanonicalizing(['owner', 'member'], $authority->roles);
        self::assertEqualsCanonicalizing(['org.read', 'members.read', 'roles.read'], $authority->scope);
    }

    public function testResolvesEmptyForNonMemberOrNoActiveOrg(): void
    {
        $member = $this->member(self::ORG);
        $role = $this->orgRole(self::ORG, 'owner');
        $this->grant($role, 'org.read');
        $this->assign($member, self::ORG, $role);

        // A different user, not a member.
        $stranger = Uuid::v7()->toRfc4122();
        self::assertSame([], $this->resolver()->resolve($stranger, self::ORG)->roles);

        // A member, but with no active org selected.
        self::assertSame([], $this->resolver()->resolve($member, null)->roles);
        self::assertSame([], $this->resolver()->resolve($member, null)->scope);
    }

    public function testSuperadminResolvesToEveryPermission(): void
    {
        $userId = $this->member(self::ORG);
        $this->assign($userId, self::ORG, $this->superadminRoleId());

        $authority = $this->resolver()->resolve($userId, null);

        self::assertSame(['superadmin'], $authority->roles);
        self::assertCount(12, $authority->scope); // the full v1 catalog
        self::assertContains('users.manage', $authority->scope);
    }

    private function resolver(): PermissionResolver
    {
        return new PermissionResolver(
            new MembershipRepository($this->orm, $this->unitOfWork),
            new MembershipRoleRepository($this->orm, $this->unitOfWork),
            new RoleRepository($this->orm, $this->unitOfWork),
            new RolePermissionRepository($this->orm, $this->unitOfWork),
            new PermissionRepository($this->orm, $this->unitOfWork),
        );
    }

    private function member(string $organizationId): string
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = Uuid::v7()->toRfc4122();
        $membership->organizationId = $organizationId;
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        (new MembershipRepository($this->orm, $this->unitOfWork))->save($membership);
        $this->unitOfWork->clear();

        return $membership->userId;
    }

    private function orgRole(string $organizationId, string $slug): string
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = $organizationId;
        $role->name = $slug;
        $role->slug = $slug;
        $role->createdAt = $now;
        $role->updatedAt = $now;
        (new RoleRepository($this->orm, $this->unitOfWork))->save($role);
        $this->unitOfWork->clear();

        return $role->id;
    }

    private function grant(string $roleId, string $permissionKey): void
    {
        $grant = new RolePermission();
        $grant->roleId = $roleId;
        $grant->permissionId = $this->permissionId($permissionKey);
        (new RolePermissionRepository($this->orm, $this->unitOfWork))->save($grant);
        $this->unitOfWork->clear();
    }

    private function assign(string $userId, string $organizationId, string $roleId): void
    {
        $membership = (new MembershipRepository($this->orm, $this->unitOfWork))
            ->findOneBy(['userId' => $userId, 'organizationId' => $organizationId]);
        self::assertInstanceOf(Membership::class, $membership);

        $link = new MembershipRole();
        $link->membershipId = $membership->id;
        $link->roleId = $roleId;
        (new MembershipRoleRepository($this->orm, $this->unitOfWork))->save($link);
        $this->unitOfWork->clear();
    }

    private function permissionId(string $key): string
    {
        return $this->idFrom('auth_permissions', ['key' => $key]);
    }

    private function superadminRoleId(): string
    {
        foreach ($this->connection()->select(['id', 'organization_id'])->from('auth_roles')->where('slug', 'superadmin')->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null) && ($row['organization_id'] ?? null) === null) {
                return $row['id'];
            }
        }

        self::fail('The superadmin system role was not seeded.');
    }

    /**
     * @param array<string, mixed> $where
     */
    private function idFrom(string $table, array $where): string
    {
        foreach ($this->connection()->select('id')->from($table)->where($where)->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        self::fail("No row in $table for the given criteria.");
    }
}
