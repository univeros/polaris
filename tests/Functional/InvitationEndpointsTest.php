<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Event\MemberInvited;
use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function is_array;
use function is_string;

/**
 * Drives the #33 invitation flow end to end: `POST/GET /orgs/{id}/invites`,
 * `DELETE /orgs/{id}/invites/{inviteId}`, and `POST /auth/invites/accept`. The emailed token
 * travels only on the {@see MemberInvited} event (mirroring email verification); acceptance
 * enforces the email match and grants exactly the invited roles. Inviting enforces the
 * `docs/auth/rbac.md` §7 invariants: no inviting an already-active member (re-invites are
 * idempotent and rotate the token), and no granting roles above the inviter's own authority.
 */
final class InvitationEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testInviteEmitsTokenAndShowsUpAsPending(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        $response = $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken);
        self::assertSame(201, $response->getStatusCode());
        self::assertNotSame('', $this->lastInviteToken());

        $pending = $this->json($this->authedGet("/orgs/$org/invites", $ownerToken))['data'] ?? [];
        self::assertCount(1, $pending);
        self::assertSame('new@example.com', $pending[0]['email'] ?? null);
        self::assertSame(['member'], $pending[0]['role_slugs'] ?? null);
    }

    public function testAcceptCreatesAnActiveMembershipWithTheInvitedRoles(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['admin']], $ownerToken);
        $token = $this->lastInviteToken();

        $invitee = $this->login('new@example.com');
        $accept = $this->authedPostJson('/auth/invites/accept', ['token' => $token], $invitee['access']);
        self::assertSame(200, $accept->getStatusCode());
        self::assertSame($org, $this->json($accept)['data']['organization_id'] ?? null);

        // The invitee is now an active member with exactly the invited roles…
        self::assertSame(200, $this->authedPostJson('/auth/switch-org', ['organization_id' => $org], $invitee['access'])->getStatusCode());
        self::assertSame(['admin'], $this->rolesOf($org, $this->userId('new@example.com'), $ownerToken));

        // …and the invitation is no longer pending.
        self::assertCount(0, $this->json($this->authedGet("/orgs/$org/invites", $ownerToken))['data'] ?? []);
    }

    public function testAcceptRequiresAMatchingEmail(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'right@example.com', 'role_slugs' => ['member']], $ownerToken);
        $token = $this->lastInviteToken();

        $wrong = $this->login('wrong@example.com');
        self::assertSame(403, $this->authedPostJson('/auth/invites/accept', ['token' => $token], $wrong['access'])->getStatusCode());

        // The invitation survives a mismatched attempt and the right user can still accept.
        $right = $this->login('right@example.com');
        self::assertSame(200, $this->authedPostJson('/auth/invites/accept', ['token' => $token], $right['access'])->getStatusCode());
    }

    public function testAcceptRejectsUnknownAndConsumedTokens(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken);
        $token = $this->lastInviteToken();

        $invitee = $this->login('new@example.com');
        self::assertSame(400, $this->authedPostJson('/auth/invites/accept', ['token' => 'not-a-real-token'], $invitee['access'])->getStatusCode());

        self::assertSame(200, $this->authedPostJson('/auth/invites/accept', ['token' => $token], $invitee['access'])->getStatusCode());
        // Single use: replaying the consumed token fails.
        self::assertSame(400, $this->authedPostJson('/auth/invites/accept', ['token' => $token], $invitee['access'])->getStatusCode());
    }

    public function testAcceptRequiresAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/auth/invites/accept', ['token' => 'whatever'])->getStatusCode());
    }

    public function testReInviteIsIdempotentAndRotatesTheToken(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken);
        $first = $this->lastInviteToken();

        self::assertSame(201, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken)->getStatusCode());
        $second = $this->lastInviteToken();
        self::assertNotSame($first, $second);

        // Still a single pending invitation; only the fresh token is valid.
        self::assertCount(1, $this->json($this->authedGet("/orgs/$org/invites", $ownerToken))['data'] ?? []);
        $invitee = $this->login('new@example.com');
        self::assertSame(400, $this->authedPostJson('/auth/invites/accept', ['token' => $first], $invitee['access'])->getStatusCode());
        self::assertSame(200, $this->authedPostJson('/auth/invites/accept', ['token' => $second], $invitee['access'])->getStatusCode());
    }

    public function testCannotInviteAnActiveMember(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->login('member@example.com');
        $this->seedMember($org, $this->userId('member@example.com'), 'member');

        $response = $this->authedPostJson("/orgs/$org/invites", ['email' => 'member@example.com', 'role_slugs' => ['member']], $ownerToken);
        self::assertSame(409, $response->getStatusCode());
    }

    public function testASuspensionCannotBeSidesteppedByInvitations(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        // A pending invitation exists, and the invitee's membership is then created suspended.
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'suspended@example.com', 'role_slugs' => ['member']], $ownerToken);
        $token = $this->lastInviteToken();
        $invitee = $this->login('suspended@example.com');
        $this->seedMember($org, $this->userId('suspended@example.com'), 'member', 'suspended');

        // Accepting must not lift the suspension…
        self::assertSame(403, $this->authedPostJson('/auth/invites/accept', ['token' => $token], $invitee['access'])->getStatusCode());
        // …and a suspended member cannot be re-invited either.
        self::assertSame(409, $this->authedPostJson("/orgs/$org/invites", ['email' => 'suspended@example.com', 'role_slugs' => ['member']], $ownerToken)->getStatusCode());
    }

    public function testAnExpiredInvitationIsHiddenAndUnacceptableButRecyclable(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken);
        $stale = $this->lastInviteToken();

        $this->connection()->update(
            'auth_invitations',
            ['expires_at' => new \DateTimeImmutable('2020-01-01 00:00:00')],
            ['organization_id' => $org],
        )->run();
        $this->unitOfWork->clear(); // the raw update bypassed the ORM heap; drop the stale entity

        self::assertCount(0, $this->json($this->authedGet("/orgs/$org/invites", $ownerToken))['data'] ?? []);
        $invitee = $this->login('new@example.com');
        self::assertSame(400, $this->authedPostJson('/auth/invites/accept', ['token' => $stale], $invitee['access'])->getStatusCode());

        // Re-inviting recycles the expired row with a fresh token and expiry.
        self::assertSame(201, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken)->getStatusCode());
        self::assertCount(1, $this->json($this->authedGet("/orgs/$org/invites", $ownerToken))['data'] ?? []);
        self::assertSame(200, $this->authedPostJson('/auth/invites/accept', ['token' => $this->lastInviteToken()], $invitee['access'])->getStatusCode());
    }

    public function testCannotRevokeAnotherOrgsInviteThroughYourOwnOrgPath(): void
    {
        [$acme, $acmeToken] = $this->orgOwnedBy('founder@example.com');
        $globex = $this->createOrg('Globex', $this->loginAccess);
        $globexToken = $this->switchOrg($this->loginAccess, $globex);
        $created = $this->json($this->authedPostJson("/orgs/$globex/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $globexToken));
        $globexInvite = (string) ($created['data']['id'] ?? '');

        // A real invite id, but presented under a different org's path: indistinguishable from unknown.
        self::assertSame(404, $this->authedDelete("/orgs/$acme/invites/$globexInvite", $acmeToken)->getStatusCode());
    }

    public function testInviterCannotGrantRolesAboveTheirOwn(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $adminToken = $this->seedActiveMember($org, 'admin@example.com', 'admin');

        // owner carries org.delete, which an admin does not hold → escalation denied.
        self::assertSame(403, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['owner']], $adminToken)->getStatusCode());
        // …but inviting within their own authority is allowed.
        self::assertSame(201, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['admin']], $adminToken)->getStatusCode());
    }

    public function testRejectsUnknownRolesAndBadEmails(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(422, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['ceo']], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPostJson("/orgs/$org/invites", ['email' => 'not-an-email', 'role_slugs' => ['member']], $ownerToken)->getStatusCode());
        self::assertSame(422, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com'], $ownerToken)->getStatusCode());
    }

    public function testPlainMemberLacksPermissionToInvite(): void
    {
        [$org] = $this->orgOwnedBy('founder@example.com');
        $memberToken = $this->seedActiveMember($org, 'member@example.com', 'member');

        // A plain member lacks members.invite → denied by the AuthorizationMiddleware.
        self::assertSame(403, $this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $memberToken)->getStatusCode());
        self::assertSame(403, $this->authedGet("/orgs/$org/invites", $memberToken)->getStatusCode());
    }

    public function testCannotManageInvitesOfAnInactiveOrg(): void
    {
        $acmeToken = $this->orgOwnedBy('founder@example.com')[1];
        $globex = $this->createOrg('Globex', $this->loginAccess); // owns Globex too, but is scoped to Acme

        self::assertSame(403, $this->authedPostJson("/orgs/$globex/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $acmeToken)->getStatusCode());
        self::assertSame(403, $this->authedGet("/orgs/$globex/invites", $acmeToken)->getStatusCode());
    }

    public function testRevokedInviteCannotBeAccepted(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');
        $created = $this->json($this->authedPostJson("/orgs/$org/invites", ['email' => 'new@example.com', 'role_slugs' => ['member']], $ownerToken));
        $inviteId = (string) ($created['data']['id'] ?? '');
        $token = $this->lastInviteToken();

        self::assertSame(200, $this->authedDelete("/orgs/$org/invites/$inviteId", $ownerToken)->getStatusCode());
        self::assertCount(0, $this->json($this->authedGet("/orgs/$org/invites", $ownerToken))['data'] ?? []);

        $invitee = $this->login('new@example.com');
        self::assertSame(400, $this->authedPostJson('/auth/invites/accept', ['token' => $token], $invitee['access'])->getStatusCode());
    }

    public function testRevokingAnUnknownInviteIsNotFound(): void
    {
        [$org, $ownerToken] = $this->orgOwnedBy('founder@example.com');

        self::assertSame(404, $this->authedDelete("/orgs/$org/invites/" . Uuid::v7()->toRfc4122(), $ownerToken)->getStatusCode());
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
        $session = $this->login($email);
        $this->loginAccess = $session['access'];
        $org = $this->createOrg('Acme', $session['access']);

        return [$org, $this->switchOrg($session['access'], $org)];
    }

    /**
     * Registers a new user, seeds them as an active member with the given role, and returns their
     * token scoped to the org.
     */
    private function seedActiveMember(string $org, string $email, string $roleSlug): string
    {
        $session = $this->login($email);
        $this->seedMember($org, $this->userId($email), $roleSlug);

        return $this->switchOrg($session['access'], $org);
    }

    private function seedMember(string $org, string $userId, string $roleSlug, string $status = 'active'): void
    {
        $now = new \DateTimeImmutable('2026-06-10 10:00:00');
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
     * The plaintext token carried on the most recent {@see MemberInvited} event.
     */
    private function lastInviteToken(): string
    {
        $invited = $this->events->ofType(MemberInvited::class);
        if ($invited === []) {
            return '';
        }

        return $invited[array_key_last($invited)]->inviteToken;
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
     * Logs the user in (registering + verifying them on first use) and returns the token pair.
     *
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
}
