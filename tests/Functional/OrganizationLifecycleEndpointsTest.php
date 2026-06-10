<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Event\MemberInvited;
use Univeros\Polaris\Event\OrganizationDeleted;
use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function is_array;
use function is_string;
use function str_repeat;

/**
 * Drives the #78 organization lifecycle verbs: `PATCH /orgs/{id}` (`org.update`) and
 * `DELETE /orgs/{id}` (`org.delete`, step-up) — a **soft delete** (`status=suspended`) that
 * emits `org.deleted` and immediately strips every member's org authority, hides the org from
 * listings, and blocks switching into it. Retention purge is ops tooling (#40), not this API.
 */
final class OrganizationLifecycleEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testOwnerRenamesTheOrganization(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        $response = $this->authedPatch("/orgs/$org", ['name' => 'Acme Worldwide'], $ownerToken);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('Acme Worldwide', $this->json($response)['data']['name'] ?? null);

        self::assertSame('Acme Worldwide', $this->json($this->authedGet("/orgs/$org", $ownerToken))['data']['name'] ?? null);
    }

    public function testAdminCanUpdateButNotDelete(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $adminToken = $this->seedActiveMember($org, 'admin@example.com', 'admin');

        // The admin template carries org.update but not org.delete.
        self::assertSame(200, $this->authedPatch("/orgs/$org", ['name' => 'Renamed by admin'], $adminToken)->getStatusCode());
        self::assertSame(403, $this->authedDelete("/orgs/$org", $adminToken)->getStatusCode());
    }

    public function testPlainMemberCanNeitherUpdateNorDelete(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $memberToken = $this->seedActiveMember($org, 'member@example.com', 'member');

        self::assertSame(403, $this->authedPatch("/orgs/$org", ['name' => 'X'], $memberToken)->getStatusCode());
        self::assertSame(403, $this->authedDelete("/orgs/$org", $memberToken)->getStatusCode());
    }

    public function testOwnerSoftDeletesTheOrganization(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(200, $this->authedDelete("/orgs/$org", $ownerToken)->getStatusCode());
        self::assertCount(1, $this->events->ofType(OrganizationDeleted::class));

        // The org's authority is gone at once: the owner's own scoped token is now powerless…
        self::assertSame(403, $this->authedGet("/orgs/$org", $ownerToken)->getStatusCode());
        // …the org disappears from listings…
        $listed = $this->json($this->authedGet('/orgs', $this->loginAccess))['data'] ?? [];
        self::assertSame([], $listed);
        // …and a fresh session cannot switch into it.
        self::assertSame(404, $this->authedPostJson('/auth/switch-org', ['organization_id' => $org], $this->loginAccess)->getStatusCode());
    }

    public function testDeleteRevokesMembersOrgScopedSessionsAndKillsPendingInvites(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $ownerRefresh = $this->lastLoginRefresh;
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'late@example.com', 'role_slugs' => ['member']], $ownerToken);
        $inviteToken = $this->lastInviteToken();

        self::assertSame(200, $this->authedDelete("/orgs/$org", $ownerToken)->getStatusCode());

        // The owner's session was scoped to the org → its refresh token is dead.
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $ownerRefresh])->getStatusCode());

        // A pre-deletion invitation must not create membership rows in the dead org.
        $invitee = $this->login('late@example.com');
        self::assertSame(400, $this->authedPostJson('/auth/invites/accept', ['token' => $inviteToken], $invitee['access'])->getStatusCode());
    }

    public function testDeleteIsIdempotentAndEmitsOneEvent(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(200, $this->authedDelete("/orgs/$org", $ownerToken)->getStatusCode());
        // The second call comes from a now-authority-less token → denied by the gate.
        self::assertSame(403, $this->authedDelete("/orgs/$org", $ownerToken)->getStatusCode());
        self::assertCount(1, $this->events->ofType(OrganizationDeleted::class));
    }

    public function testSuperadminCanManageAnyOrgAndSeesRealNotFound(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $admin = $this->superadmin();

        // Cross-org access via the superadmin override.
        self::assertSame(200, $this->authedPatch("/orgs/$org", ['name' => 'Operated'], $admin)->getStatusCode());

        // Superadmins pass the active-org guard, so an unknown id is a genuine 404.
        $unknown = Uuid::v7()->toRfc4122();
        self::assertSame(404, $this->authedPatch("/orgs/$unknown", ['name' => 'X'], $admin)->getStatusCode());
        self::assertSame(404, $this->authedDelete("/orgs/$unknown", $admin)->getStatusCode());
    }

    public function testRejectsBadNames(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(422, $this->authedPatch("/orgs/$org", ['name' => '  '], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPatch("/orgs/$org", ['name' => str_repeat('x', 161)], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPatch("/orgs/$org", [], $ownerToken)->getStatusCode());
    }

    public function testCannotManageAnInactiveOrg(): void
    {
        $acmeToken = $this->orgOwnedBy('founder@example.com')[1];
        $globex = $this->createOrg('Globex', $this->loginAccess); // owns Globex too, but is scoped to Acme

        self::assertSame(403, $this->authedPatch("/orgs/$globex", ['name' => 'X'], $acmeToken)->getStatusCode());
        self::assertSame(403, $this->authedDelete("/orgs/$globex", $acmeToken)->getStatusCode());
    }

    // --- helpers ---

    private string $loginAccess = '';
    private string $lastLoginRefresh = '';

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
        $userId = $this->userId($email);

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

        return $this->switchOrg($session['access'], $org);
    }

    private function superadmin(): string
    {
        $session = $this->login('operator@example.com');
        $root = $this->createOrg('Root', $session['access']);

        $membershipId = $this->idFrom('auth_memberships', ['user_id' => $this->userId('operator@example.com')]);
        $this->connection()->insert('auth_membership_roles')->values([
            'membership_id' => $membershipId,
            'role_id' => $this->idFrom('auth_roles', ['slug' => 'superadmin', 'organization_id' => null]),
        ])->run();

        // Re-scope so the fresh token's roles claim carries the superadmin override (the
        // active-org guard reads claims; the Gate re-resolves from the DB either way).
        return $this->switchOrg($session['access'], $root);
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
        $this->lastLoginRefresh = (string) ($body['data']['refresh_token'] ?? '');

        return [
            'access' => (string) ($body['data']['access_token'] ?? ''),
            'refresh' => $this->lastLoginRefresh,
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

    private function lastInviteToken(): string
    {
        $invited = $this->events->ofType(MemberInvited::class);

        return $invited === [] ? '' : $invited[array_key_last($invited)]->inviteToken;
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
