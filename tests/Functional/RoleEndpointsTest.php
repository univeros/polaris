<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function in_array;
use function is_array;
use function is_string;

/**
 * Drives the #34 roles management API: `GET/POST /orgs/{id}/roles`,
 * `PATCH/DELETE /orgs/{id}/roles/{roleId}`, and the `GET /permissions` catalog. Custom roles may
 * only carry permission keys the actor themselves holds (no self-escalation by editing a role you
 * are assigned), the cloned `owner` role and global system roles are immutable, and deleting a
 * role detaches it from every membership via the DB cascade.
 */
final class RoleEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testListsTheClonedTemplateRolesWithTheirPermissions(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        $roles = $this->json($this->authedGet("/orgs/$org/roles", $ownerToken))['data'] ?? [];
        $bySlug = $this->indexBySlug($roles);

        self::assertSame(['admin', 'member', 'owner'], $this->sortedKeys($bySlug));
        self::assertContains('org.delete', $bySlug['owner']['permission_keys'] ?? []);
        self::assertNotContains('org.delete', $bySlug['admin']['permission_keys'] ?? []);
        self::assertContains('roles.read', $bySlug['member']['permission_keys'] ?? []);
    }

    public function testPermissionsCatalogIsAvailableToAnyAuthenticatedUser(): void
    {
        $session = $this->login('someone@example.com');

        $catalog = $this->json($this->authedGet('/permissions', $session['access']))['data'] ?? [];
        $keys = [];
        foreach ($catalog as $permission) {
            if (is_array($permission) && is_string($permission['key'] ?? null)) {
                $keys[] = $permission['key'];
            }
        }
        self::assertContains('members.invite', $keys);
        self::assertContains('org.delete', $keys);

        self::assertSame(401, $this->get('/permissions')->getStatusCode());
    }

    public function testOwnerCreatesACustomRoleAndItIsGrantable(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        $response = $this->authedPostJson("/orgs/$org/roles", [
            'name' => 'Support',
            'slug' => 'support',
            'description' => 'Read-only support staff',
            'permission_keys' => ['org.read', 'members.read'],
        ], $ownerToken);
        self::assertSame(201, $response->getStatusCode());
        $roleId = (string) ($this->json($response)['data']['id'] ?? '');
        self::assertNotSame('', $roleId);

        $bySlug = $this->indexBySlug($this->json($this->authedGet("/orgs/$org/roles", $ownerToken))['data'] ?? []);
        self::assertSame(['org.read', 'members.read'], $bySlug['support']['permission_keys'] ?? null);

        // The new role is assignable through the member-roles endpoint.
        $member = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $member, 'member');
        self::assertSame(200, $this->authedPatch("/orgs/$org/members/$member/roles", ['role_slugs' => ['support']], $ownerToken)->getStatusCode());
    }

    public function testDuplicateSlugConflicts(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(409, $this->authedPostJson("/orgs/$org/roles", [
            'name' => 'Member Two',
            'slug' => 'member',
            'permission_keys' => ['org.read'],
        ], $ownerToken)->getStatusCode());
    }

    public function testRejectsUnknownPermissionKeysAndBadInput(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(422, $this->authedPostJson("/orgs/$org/roles", [
            'name' => 'X',
            'slug' => 'x',
            'permission_keys' => ['does.not.exist'],
        ], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPostJson("/orgs/$org/roles", [
            'slug' => 'x',
            'permission_keys' => ['org.read'],
        ], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPostJson("/orgs/$org/roles", [
            'name' => 'X',
            'slug' => 'Not A Slug!',
            'permission_keys' => ['org.read'],
        ], $ownerToken)->getStatusCode());
    }

    public function testActorCannotPutPermissionsTheyDoNotHoldIntoARole(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $adminToken = $this->seedActiveMember($org, 'admin@example.com', 'admin');

        // An admin holds roles.manage but not org.delete — packing it into any role is denied…
        self::assertSame(403, $this->authedPostJson("/orgs/$org/roles", [
            'name' => 'Sneaky',
            'slug' => 'sneaky',
            'permission_keys' => ['org.delete'],
        ], $adminToken)->getStatusCode());

        // …including editing a role they already hold (the self-escalation path).
        $adminRole = $this->roleId($org, 'admin');
        self::assertSame(403, $this->authedPatch("/orgs/$org/roles/$adminRole", [
            'permission_keys' => ['org.delete'],
        ], $adminToken)->getStatusCode());
    }

    public function testUpdateChangesNameAndPermissions(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $created = $this->json($this->authedPostJson("/orgs/$org/roles", [
            'name' => 'Support',
            'slug' => 'support',
            'permission_keys' => ['org.read'],
        ], $ownerToken));
        $roleId = (string) ($created['data']['id'] ?? '');

        $response = $this->authedPatch("/orgs/$org/roles/$roleId", [
            'name' => 'Support Tier 2',
            'permission_keys' => ['org.read', 'members.read'],
        ], $ownerToken);
        self::assertSame(200, $response->getStatusCode());

        $bySlug = $this->indexBySlug($this->json($this->authedGet("/orgs/$org/roles", $ownerToken))['data'] ?? []);
        self::assertSame('Support Tier 2', $bySlug['support']['name'] ?? null);
        self::assertSame(['org.read', 'members.read'], $bySlug['support']['permission_keys'] ?? null);
    }

    public function testTheOwnerRoleIsImmutable(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $ownerRole = $this->roleId($org, 'owner');

        self::assertSame(403, $this->authedPatch("/orgs/$org/roles/$ownerRole", ['name' => 'God'], $ownerToken)->getStatusCode());
        self::assertSame(403, $this->authedDelete("/orgs/$org/roles/$ownerRole", $ownerToken)->getStatusCode());
    }

    public function testTheClonedTemplatesAreEditableButNotDeletable(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        // admin/member stay tenant-editable…
        $adminRole = $this->roleId($org, 'admin');
        self::assertSame(200, $this->authedPatch("/orgs/$org/roles/$adminRole", ['name' => 'Manager'], $ownerToken)->getStatusCode());

        // …but deleting them would cascade-strip members and break slug-based assignment.
        self::assertSame(403, $this->authedDelete("/orgs/$org/roles/$adminRole", $ownerToken)->getStatusCode());
        self::assertSame(403, $this->authedDelete("/orgs/$org/roles/" . $this->roleId($org, 'member'), $ownerToken)->getStatusCode());
    }

    public function testUpdateCanStripAllPermissionsFromARole(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $created = $this->json($this->authedPostJson("/orgs/$org/roles", [
            'name' => 'Support',
            'slug' => 'support',
            'permission_keys' => ['org.read'],
        ], $ownerToken));
        $roleId = (string) ($created['data']['id'] ?? '');

        self::assertSame(200, $this->authedPatch("/orgs/$org/roles/$roleId", ['permission_keys' => []], $ownerToken)->getStatusCode());
        $bySlug = $this->indexBySlug($this->json($this->authedGet("/orgs/$org/roles", $ownerToken))['data'] ?? []);
        self::assertSame([], $bySlug['support']['permission_keys'] ?? null);
    }

    public function testGlobalSystemRolesAreNotReachableThroughTheOrgPath(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $superadmin = $this->systemRoleId('superadmin');

        // Another scope's role is indistinguishable from an unknown one.
        self::assertSame(404, $this->authedPatch("/orgs/$org/roles/$superadmin", ['name' => 'Pwned'], $ownerToken)->getStatusCode());
        self::assertSame(404, $this->authedDelete("/orgs/$org/roles/$superadmin", $ownerToken)->getStatusCode());
        $listed = $this->indexBySlug($this->json($this->authedGet("/orgs/$org/roles", $ownerToken))['data'] ?? []);
        self::assertArrayNotHasKey('superadmin', $listed);
    }

    public function testDeletingARoleDetachesItFromMembers(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $created = $this->json($this->authedPostJson("/orgs/$org/roles", [
            'name' => 'Support',
            'slug' => 'support',
            'permission_keys' => ['org.read', 'members.read'],
        ], $ownerToken));
        $roleId = (string) ($created['data']['id'] ?? '');

        $member = Uuid::v7()->toRfc4122();
        $this->seedMember($org, $member, 'support');

        self::assertSame(200, $this->authedDelete("/orgs/$org/roles/$roleId", $ownerToken)->getStatusCode());

        $bySlug = $this->indexBySlug($this->json($this->authedGet("/orgs/$org/roles", $ownerToken))['data'] ?? []);
        self::assertArrayNotHasKey('support', $bySlug);
        self::assertSame([], $this->rolesOf($org, $member, $ownerToken));
    }

    public function testPlainMemberLacksPermissionToManageRoles(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $memberToken = $this->seedActiveMember($org, 'member@example.com', 'member');

        // members hold roles.read but not roles.manage.
        self::assertSame(200, $this->authedGet("/orgs/$org/roles", $memberToken)->getStatusCode());
        self::assertSame(403, $this->authedPostJson("/orgs/$org/roles", [
            'name' => 'X',
            'slug' => 'x',
            'permission_keys' => ['org.read'],
        ], $memberToken)->getStatusCode());
        self::assertSame(403, $this->authedPatch("/orgs/$org/roles/" . $this->roleId($org, 'member'), ['name' => 'X'], $memberToken)->getStatusCode());
        self::assertSame(403, $this->authedDelete("/orgs/$org/roles/" . $this->roleId($org, 'member'), $memberToken)->getStatusCode());
    }

    public function testCannotManageRolesOfAnInactiveOrg(): void
    {
        $acmeToken = $this->orgOwnedBy('founder@example.com')[1];
        $globex = $this->createOrg('Globex', $this->loginAccess); // owns Globex too, but is scoped to Acme

        self::assertSame(403, $this->authedGet("/orgs/$globex/roles", $acmeToken)->getStatusCode());
        self::assertSame(403, $this->authedPostJson("/orgs/$globex/roles", [
            'name' => 'X',
            'slug' => 'x',
            'permission_keys' => ['org.read'],
        ], $acmeToken)->getStatusCode());
    }

    public function testUnknownRoleIsNotFound(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $unknown = Uuid::v7()->toRfc4122();

        self::assertSame(404, $this->authedPatch("/orgs/$org/roles/$unknown", ['name' => 'X'], $ownerToken)->getStatusCode());
        self::assertSame(404, $this->authedDelete("/orgs/$org/roles/$unknown", $ownerToken)->getStatusCode());
    }

    // --- helpers ---

    private string $loginAccess = '';

    /**
     * @return array{0: string, 1: string}
     */
    private function orgOwnedBy(string $email): array
    {
        $session = $this->login($email);
        $this->loginAccess = $session['access'];
        $org = $this->createOrg('Acme', $session['access']);

        return [$org, $this->switchOrg($session['access'], $org)];
    }

    private function seedActiveMember(string $org, string $email, string $roleSlug): string
    {
        $session = $this->login($email);
        $this->seedMember($org, $this->userId($email), $roleSlug);

        return $this->switchOrg($session['access'], $org);
    }

    private function seedMember(string $org, string $userId, string $roleSlug): void
    {
        $now = new \DateTimeImmutable('2026-06-10 10:00:00');
        $membershipId = Uuid::v7()->toRfc4122();
        $this->connection()->insert('auth_memberships')->values([
            'id' => $membershipId,
            'user_id' => $userId,
            'organization_id' => $org,
            'status' => 'active',
            'created_at' => $now,
            'updated_at' => $now,
        ])->run();
        $this->connection()->insert('auth_membership_roles')->values([
            'membership_id' => $membershipId,
            'role_id' => $this->roleId($org, $roleSlug),
        ])->run();
    }

    /**
     * @param list<mixed> $roles
     *
     * @return array<string, array<string, mixed>>
     */
    private function indexBySlug(array $roles): array
    {
        $bySlug = [];
        foreach ($roles as $role) {
            if (is_array($role) && is_string($role['slug'] ?? null)) {
                $bySlug[$role['slug']] = $role;
            }
        }

        return $bySlug;
    }

    /**
     * @param array<string, mixed> $map
     *
     * @return list<string>
     */
    private function sortedKeys(array $map): array
    {
        $keys = array_keys($map);
        sort($keys);

        return $keys;
    }

    /**
     * @return list<string>
     */
    private function rolesOf(string $org, string $userId, string $token): array
    {
        foreach ($this->json($this->authedGet("/orgs/$org/members", $token))['data'] ?? [] as $member) {
            if (is_array($member) && ($member['user_id'] ?? null) === $userId && is_array($member['roles'] ?? null)) {
                $roles = [];
                foreach ($member['roles'] as $role) {
                    if (is_string($role)) {
                        $roles[] = $role;
                    }
                }

                return $roles;
            }
        }

        return [];
    }

    /**
     * @return array{access: string, refresh: string}
     */
    private function login(string $email): array
    {
        $register = $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        if ($register->getStatusCode() < 300) {
            $registered = $this->events->ofType(UserRegistered::class);
            $token = $registered[array_key_last($registered)]->verificationToken;
            $this->postJson('/auth/email/verify', ['token' => $token]);
            $this->unitOfWork->clear();
        }

        $body = $this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]));

        return [
            'access' => (string) ($body['data']['access_token'] ?? ''),
            'refresh' => (string) ($body['data']['refresh_token'] ?? ''),
        ];
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
        foreach ($this->connection()->select('id')->from('auth_users')->where(['email' => $email])->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        self::fail("No user with email $email.");
    }

    private function roleId(string $organizationId, string $slug): string
    {
        foreach ($this->connection()->select('id')->from('auth_roles')->where(['organization_id' => $organizationId, 'slug' => $slug])->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        self::fail("No $slug role for organization $organizationId.");
    }

    private function systemRoleId(string $slug): string
    {
        foreach ($this->connection()->select('id')->from('auth_roles')->where(['slug' => $slug, 'organization_id' => null])->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        self::fail("No global $slug role.");
    }
}
