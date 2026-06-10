<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Http\Contracts\TokenInterface;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Authorization\Gate;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Persistence\MembershipRepository;
use Univeros\Polaris\Persistence\MembershipRoleRepository;
use Univeros\Polaris\Persistence\PermissionRepository;
use Univeros\Polaris\Persistence\RolePermissionRepository;
use Univeros\Polaris\Persistence\RoleRepository;
use Univeros\Polaris\Persistence\UserRepository;

use function is_array;
use function is_string;

/**
 * Verifies the #36 {@see Gate} against a real driver: a programmatic `authorize()` passes for a
 * permission the caller holds in their active org and throws {@see AuthorizationException} for one
 * they do not.
 */
final class GateTest extends DatabaseTestCase
{
    private const string ORG = '01910000-0000-7000-8000-0000000000bb';

    public function testAuthorizePassesForAHeldPermission(): void
    {
        $token = $this->memberWith('members.read');

        $this->gate()->authorize($token, 'members.read');

        $this->expectNotToPerformAssertions();
    }

    public function testAuthorizeThrowsForAMissingPermission(): void
    {
        $token = $this->memberWith('members.read');

        self::assertFalse($this->gate()->allows($token, 'members.invite'));

        $this->expectException(AuthorizationException::class);
        $this->gate()->authorize($token, 'members.invite');
    }

    private function gate(): Gate
    {
        return new Gate(new PermissionResolver(
            new UserRepository($this->orm, $this->unitOfWork),
            new MembershipRepository($this->orm, $this->unitOfWork),
            new MembershipRoleRepository($this->orm, $this->unitOfWork),
            new RoleRepository($this->orm, $this->unitOfWork),
            new RolePermissionRepository($this->orm, $this->unitOfWork),
            new PermissionRepository($this->orm, $this->unitOfWork),
        ));
    }

    /**
     * Creates a member of {@see self::ORG} holding exactly the given permission via a single role,
     * and returns a token scoped to that org.
     */
    private function memberWith(string $permissionKey): TokenInterface
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
        $userId = Uuid::v7()->toRfc4122();

        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = $userId;
        $membership->organizationId = self::ORG;
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        (new MembershipRepository($this->orm, $this->unitOfWork))->save($membership);

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = self::ORG;
        $role->name = 'limited';
        $role->slug = 'limited';
        $role->createdAt = $now;
        $role->updatedAt = $now;
        (new RoleRepository($this->orm, $this->unitOfWork))->save($role);

        $grant = new RolePermission();
        $grant->roleId = $role->id;
        $grant->permissionId = $this->permissionId($permissionKey);
        (new RolePermissionRepository($this->orm, $this->unitOfWork))->save($grant);

        $link = new MembershipRole();
        $link->membershipId = $membership->id;
        $link->roleId = $role->id;
        (new MembershipRoleRepository($this->orm, $this->unitOfWork))->save($link);

        $this->unitOfWork->clear();

        return new class ($userId, self::ORG) implements TokenInterface {
            public function __construct(private readonly string $sub, private readonly string $org)
            {
            }

            public function getToken(): string
            {
                return '';
            }

            public function getMetadata(?string $key = null): mixed
            {
                return match ($key) {
                    'sub' => $this->sub,
                    'org' => $this->org,
                    default => null,
                };
            }
        };
    }

    private function permissionId(string $key): string
    {
        foreach ($this->connection()->select('id')->from('auth_permissions')->where('key', $key)->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        self::fail("Permission $key was not seeded.");
    }
}
