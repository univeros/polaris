<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function is_array;
use function is_string;

/**
 * Drives the #32 member-management endpoints and, above all, their **security invariants**
 * (`docs/auth/rbac.md` §7): no privilege escalation, owners are protected from non-owners, and the
 * last owner cannot be demoted or removed. Members beyond the creator are seeded directly (the
 * invite flow that adds them in production is #33).
 */
final class MembershipEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testListsMembersWithTheirRoles(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->seedMember($org, Uuid::v7()->toRfc4122(), 'member');

        $list = $this->json($this->authedGet("/orgs/$org/members", $ownerToken))['data'] ?? [];
        self::assertCount(2, $list);
        $roles = [];
        foreach ($list as $member) {
            foreach (is_array($member['roles'] ?? null) ? $member['roles'] : [] as $role) {
                $roles[] = $role;
            }
        }
        self::assertContains('owner', $roles);
        self::assertContains('member', $roles);
    }

    public function testInvitedAndSuspendedEmailsAreGatedOnMembersInvite(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $memberToken = $this->seedActiveMember($org, 'member@example.com', 'member');
        $this->login('invited@example.com');
        $invited = $this->userId('invited@example.com');
        $this->seedMember($org, $invited, 'member', 'invited');
        $this->login('suspended@example.com');
        $suspended = $this->userId('suspended@example.com');
        $this->seedMember($org, $suspended, 'member', 'suspended');

        // A plain members.read holder sees active members' emails, but not those of
        // invited/suspended members (issue #97).
        $emails = $this->emailsByUserId($org, $memberToken);
        self::assertSame('founder@example.com', $emails[$this->userId('founder@example.com')]);
        self::assertNull($emails[$invited]);
        self::assertNull($emails[$suspended]);

        // An owner holds members.invite and sees the full roster.
        $emails = $this->emailsByUserId($org, $ownerToken);
        self::assertSame('invited@example.com', $emails[$invited]);
        self::assertSame('suspended@example.com', $emails[$suspended]);
    }

    public function testOwnerCanChangeAMembersRoles(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $target, 'member');

        $response = $this->authedPatch("/orgs/$org/members/$target/roles", ['role_slugs' => ['admin']], $ownerToken);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['admin'], $this->rolesOf($org, $target, $ownerToken));
    }

    public function testAdminCannotEscalateAMemberToOwner(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $adminToken = $this->seedActiveMember($org, 'admin@example.com', 'admin');
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $target, 'member');

        // owner carries org.delete, which an admin does not hold → escalation denied.
        $response = $this->authedPatch("/orgs/$org/members/$target/roles", ['role_slugs' => ['owner']], $adminToken);
        self::assertSame(403, $response->getStatusCode());
    }

    public function testAdminCanGrantNonEscalatingRoles(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $adminToken = $this->seedActiveMember($org, 'admin@example.com', 'admin');
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $target, 'member');

        // member → admin is within the admin's own authority, so it is allowed.
        self::assertSame(200, $this->authedPatch("/orgs/$org/members/$target/roles", ['role_slugs' => ['admin']], $adminToken)->getStatusCode());
    }

    public function testAdminCannotModifyAnOwner(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $owner = $this->userId('founder@example.com');
        $adminToken = $this->seedActiveMember($org, 'admin@example.com', 'admin');

        $response = $this->authedPatch("/orgs/$org/members/$owner/roles", ['role_slugs' => ['member']], $adminToken);
        self::assertSame(403, $response->getStatusCode());
    }

    public function testCannotDemoteTheLastOwner(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $owner = $this->userId('founder@example.com');

        $response = $this->authedPatch("/orgs/$org/members/$owner/roles", ['role_slugs' => ['member']], $ownerToken);
        self::assertSame(409, $response->getStatusCode());
    }

    public function testCannotRemoveTheLastOwner(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $owner = $this->userId('founder@example.com');

        self::assertSame(409, $this->authedDelete("/orgs/$org/members/$owner", $ownerToken)->getStatusCode());
    }

    public function testOwnerCanRemoveANonOwnerMember(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $target, 'member');

        self::assertSame(200, $this->authedDelete("/orgs/$org/members/$target", $ownerToken)->getStatusCode());
        self::assertCount(1, $this->json($this->authedGet("/orgs/$org/members", $ownerToken))['data'] ?? []);
    }

    public function testCanDemoteAnOwnerWhenAnotherOwnerRemains(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $secondOwner = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $secondOwner, 'owner');

        // Two owners, so demoting one is allowed.
        self::assertSame(200, $this->authedPatch("/orgs/$org/members/$secondOwner/roles", ['role_slugs' => ['member']], $ownerToken)->getStatusCode());
    }

    public function testMemberLacksPermissionToManageMembers(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $memberToken = $this->seedActiveMember($org, 'member@example.com', 'member');
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $target, 'member');

        // A plain member lacks members.update → the AuthorizationMiddleware denies it.
        self::assertSame(403, $this->authedPatch("/orgs/$org/members/$target/roles", ['role_slugs' => ['member']], $memberToken)->getStatusCode());
    }

    /**
     * An owner of one org, scoped to it, creates and seeds a member in a different org, then is
     * denied managing it from the wrong active-org context.
     */
    public function testCannotManageMembersOfAnInactiveOrg(): void
    {
        $acmeToken = $this->orgOwnedBy('founder@example.com')[1];
        $globex = $this->createOrg('Globex', $this->loginAccess); // owns Globex too, but is scoped to Acme
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($globex, $target, 'member');

        self::assertSame(403, $this->authedGet("/orgs/$globex/members", $acmeToken)->getStatusCode());
    }

    // --- helpers ---

    private string $loginAccess = '';

    /**
     * Registers/verifies/logs in the user, creates an org they own, and returns [orgId, scopedToken].
     *
     * @return array{0: string, 1: string}
     */
    private function orgOwnedBy(string $email): array
    {
        $access = $this->loginAccess = $this->login($email);
        $org = $this->createOrg('Acme', $access);

        return [$org, $this->switchOrg($access, $org)];
    }

    /**
     * Registers a new user, seeds them as an active member of the org with the given role, and
     * returns their token scoped to that org.
     */
    private function seedActiveMember(string $org, string $email, string $roleSlug): string
    {
        $access = $this->login($email);
        $this->seedMember($org, $this->userId($email), $roleSlug);

        return $this->switchOrg($access, $org);
    }

    private function seedMember(string $org, string $userId, string $roleSlug, string $status = 'active'): void
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
        $membershipId = Uuid::v7()->toRfc4122();
        $this->connection()->insert('auth_memberships')->values([
            'id' => $membershipId,
            'user_id' => $userId,
            'organization_id' => $org,
            'status' => $status,
            'created_at' => $now,
            'updated_at' => $now,
        ])->run();
        $this->connection()->insert('auth_membership_roles')->values([
            'membership_id' => $membershipId,
            'role_id' => $this->roleId($org, $roleSlug),
        ])->run();
    }

    /**
     * The listed roster as user_id → email (null when the endpoint withheld it).
     *
     * @return array<string, string|null>
     */
    private function emailsByUserId(string $org, string $token): array
    {
        $emails = [];
        foreach ($this->json($this->authedGet("/orgs/$org/members", $token))['data'] ?? [] as $member) {
            if (is_array($member) && is_string($member['user_id'] ?? null)) {
                $email = $member['email'] ?? null;
                $emails[$member['user_id']] = is_string($email) ? $email : null;
            }
        }

        return $emails;
    }

    /**
     * @return list<string>
     */
    private function rolesOf(string $org, string $userId, string $token): array
    {
        foreach ($this->json($this->authedGet("/orgs/$org/members", $token))['data'] ?? [] as $member) {
            if (($member['user_id'] ?? null) === $userId && is_array($member['roles'] ?? null)) {
                return $this->stringList($member['roles']);
            }
        }

        return [];
    }

    /**
     * @param array<int, mixed> $values
     *
     * @return list<string>
     */
    private function stringList(array $values): array
    {
        $strings = [];
        foreach ($values as $value) {
            if (is_string($value)) {
                $strings[] = $value;
            }
        }

        return $strings;
    }

    private function login(string $email): string
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $token = $registered[array_key_last($registered)]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

        $body = $this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]));

        return (string) ($body['data']['access_token'] ?? '');
    }

    private function createOrg(string $name, string $access): string
    {
        $data = $this->json($this->authedPostJson('/orgs', ['name' => $name], $access))['data'] ?? [];

        return is_string($data['id'] ?? null) ? $data['id'] : '';
    }

    private function switchOrg(string $access, string $organizationId): string
    {
        $body = $this->json($this->authedPostJson('/auth/switch-org', ['organization_id' => $organizationId], $access));

        return (string) ($body['data']['access_token'] ?? '');
    }

    private function userId(string $email): string
    {
        return $this->idFrom('auth_users', ['email' => $email]);
    }

    private function roleId(string $organizationId, string $slug): string
    {
        return $this->idFrom('auth_roles', ['organization_id' => $organizationId, 'slug' => $slug]);
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
