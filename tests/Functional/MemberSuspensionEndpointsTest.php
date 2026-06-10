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
 * Drives the #82 membership status lifecycle: `PATCH /orgs/{id}/members/{userId}` suspends or
 * reactivates a member. Suspension must **immediately revoke the member's org-scoped sessions**
 * (refresh-token families whose current context is the org) while leaving their other sessions
 * alone, and the owner-protection / last-active-owner invariants of `docs/auth/rbac.md` §7 apply.
 */
final class MemberSuspensionEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testSuspensionRevokesTheMembersOrgScopedSession(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $member = $this->joinAsActiveMember($org, 'member@example.com', 'member');

        $response = $this->authedPatch("/orgs/$org/members/{$member['userId']}", ['status' => 'suspended'], $ownerToken);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('suspended', $this->json($response)['data']['status'] ?? null);
        self::assertSame('suspended', $this->statusOf($org, $member['userId'], $ownerToken));

        // The member's session was re-scoped to the org by switch-org → revoked outright.
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $member['refresh']])->getStatusCode());
    }

    public function testSuspensionLeavesSessionsOfOtherOrgsAlone(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $member = $this->joinAsActiveMember($org, 'member@example.com', 'member');

        // A second session that never switched into the org keeps its (org-less) context.
        $unscoped = $this->plainLogin('member@example.com');

        self::assertSame(200, $this->authedPatch("/orgs/$org/members/{$member['userId']}", ['status' => 'suspended'], $ownerToken)->getStatusCode());

        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $member['refresh']])->getStatusCode());
        self::assertSame(200, $this->postJson('/auth/token/refresh', ['refresh_token' => $unscoped['refresh']])->getStatusCode());
    }

    public function testSuspendedMemberCannotSwitchIntoTheOrgUntilReactivated(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $member = $this->joinAsActiveMember($org, 'member@example.com', 'member');

        self::assertSame(200, $this->authedPatch("/orgs/$org/members/{$member['userId']}", ['status' => 'suspended'], $ownerToken)->getStatusCode());

        // While suspended, a fresh session cannot adopt the org as its active context.
        $fresh = $this->plainLogin('member@example.com');
        self::assertSame(403, $this->authedPostJson('/auth/switch-org', ['organization_id' => $org], $fresh['access'])->getStatusCode());

        // Reactivation restores access.
        self::assertSame(200, $this->authedPatch("/orgs/$org/members/{$member['userId']}", ['status' => 'active'], $ownerToken)->getStatusCode());
        self::assertSame('active', $this->statusOf($org, $member['userId'], $ownerToken));
        self::assertSame(200, $this->authedPostJson('/auth/switch-org', ['organization_id' => $org], $fresh['access'])->getStatusCode());
    }

    public function testSuspendedMembersExistingAccessTokenIsDeniedImmediately(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $admin = $this->joinAsActiveMember($org, 'admin@example.com', 'admin');

        self::assertSame(200, $this->authedGet("/orgs/$org/members", $admin['scoped'])->getStatusCode());

        self::assertSame(200, $this->authedPatch("/orgs/$org/members/{$admin['userId']}", ['status' => 'suspended'], $ownerToken)->getStatusCode());

        // No revocation window for gated routes: the Gate re-resolves authority from the database
        // on every request, so even the not-yet-expired access token loses the org instantly.
        self::assertSame(403, $this->authedGet("/orgs/$org/members", $admin['scoped'])->getStatusCode());
    }

    public function testAnOwnerCanSuspendThemselvesWhenAnotherOwnerRemains(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->joinAsActiveMember($org, 'cofounder@example.com', 'owner');
        $founder = $this->userId('founder@example.com');

        self::assertSame(200, $this->authedPatch("/orgs/$org/members/$founder", ['status' => 'suspended'], $ownerToken)->getStatusCode());
        self::assertSame(403, $this->authedGet("/orgs/$org/members", $ownerToken)->getStatusCode());
    }

    public function testAdminCannotSuspendAnOwner(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $owner = $this->userId('founder@example.com');
        $admin = $this->joinAsActiveMember($org, 'admin@example.com', 'admin');

        self::assertSame(403, $this->authedPatch("/orgs/$org/members/$owner", ['status' => 'suspended'], $admin['scoped'])->getStatusCode());
    }

    public function testCannotSuspendTheLastActiveOwner(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $owner = $this->userId('founder@example.com');

        self::assertSame(409, $this->authedPatch("/orgs/$org/members/$owner", ['status' => 'suspended'], $ownerToken)->getStatusCode());
    }

    public function testAnOwnerCanBeSuspendedWhenAnotherActiveOwnerRemains(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $secondOwner = $this->joinAsActiveMember($org, 'cofounder@example.com', 'owner');

        self::assertSame(200, $this->authedPatch("/orgs/$org/members/{$secondOwner['userId']}", ['status' => 'suspended'], $ownerToken)->getStatusCode());
    }

    public function testRejectsAnUnknownStatus(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $member = $this->joinAsActiveMember($org, 'member@example.com', 'member');

        self::assertSame(422, $this->authedPatch("/orgs/$org/members/{$member['userId']}", ['status' => 'banned'], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPatch("/orgs/$org/members/{$member['userId']}", [], $ownerToken)->getStatusCode());
    }

    public function testPlainMemberLacksPermissionToSuspend(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $member = $this->joinAsActiveMember($org, 'member@example.com', 'member');
        $target = $this->joinAsActiveMember($org, 'target@example.com', 'member');

        // members.update is required; a plain member is denied by the AuthorizationMiddleware.
        self::assertSame(403, $this->authedPatch("/orgs/$org/members/{$target['userId']}", ['status' => 'suspended'], $member['scoped'])->getStatusCode());
    }

    public function testCannotSuspendMembersOfAnInactiveOrg(): void
    {
        $acmeToken = $this->orgOwnedBy('founder@example.com')[1];
        $globex = $this->createOrg('Globex', $this->loginAccess); // owns Globex too, but is scoped to Acme
        $target = Uuid::v7()->toRfc4122();
        $this->seedMember($globex, $target, 'member');

        self::assertSame(403, $this->authedPatch("/orgs/$globex/members/$target", ['status' => 'suspended'], $acmeToken)->getStatusCode());
    }

    public function testUnknownMemberIsNotFound(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        $stranger = Uuid::v7()->toRfc4122();
        self::assertSame(404, $this->authedPatch("/orgs/$org/members/$stranger", ['status' => 'suspended'], $ownerToken)->getStatusCode());
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
        $session = $this->plainLogin($email);
        $this->loginAccess = $session['access'];
        $org = $this->createOrg('Acme', $session['access']);

        return [$org, $this->switchOrg($session['access'], $org)];
    }

    /**
     * Registers a new user, seeds them as an active member with the given role, and switches their
     * session into the org — so the session is org-scoped, as after a real invite acceptance.
     *
     * @return array{userId: string, access: string, refresh: string, scoped: string}
     */
    private function joinAsActiveMember(string $org, string $email, string $roleSlug): array
    {
        $session = $this->plainLogin($email);
        $userId = $this->userId($email);
        $this->seedMember($org, $userId, $roleSlug);

        return [
            'userId' => $userId,
            'access' => $session['access'],
            'refresh' => $session['refresh'],
            'scoped' => $this->switchOrg($session['access'], $org),
        ];
    }

    /**
     * Logs the user in (registering + verifying them on first use) and returns the token pair.
     *
     * @return array{access: string, refresh: string}
     */
    private function plainLogin(string $email): array
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

    private function seedMember(string $org, string $userId, string $roleSlug): void
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
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

    private function statusOf(string $org, string $userId, string $token): ?string
    {
        foreach ($this->json($this->authedGet("/orgs/$org/members", $token))['data'] ?? [] as $member) {
            if (is_array($member) && ($member['user_id'] ?? null) === $userId) {
                return is_string($member['status'] ?? null) ? $member['status'] : null;
            }
        }

        return null;
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
}
