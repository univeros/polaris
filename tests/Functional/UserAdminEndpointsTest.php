<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Event\UserDisabled;
use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function is_array;
use function is_string;
use function str_contains;
use function str_repeat;

/**
 * Drives the #37 users admin endpoints: `GET/PATCH/DELETE /users/{id}` (self or admin) and
 * `POST /users/{id}/disable|enable` (admin only, `users.manage` — held only by `superadmin`).
 * Disabling revokes the target's sessions and blocks login; deletion **anonymizes** (hashed email,
 * nulled profile, dead sessions) while keeping the row for referential/audit integrity.
 */
final class UserAdminEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testUserReadsAndUpdatesTheirOwnProfile(): void
    {
        $session = $this->login('me@example.com');
        $id = $this->userId('me@example.com');

        $read = $this->json($this->authedGet("/users/$id", $session['access']));
        self::assertSame('me@example.com', $read['data']['email'] ?? null);
        self::assertSame('active', $read['data']['status'] ?? null);

        self::assertSame(200, $this->authedPatch("/users/$id", ['display_name' => 'Tony'], $session['access'])->getStatusCode());
        $read = $this->json($this->authedGet("/users/$id", $session['access']));
        self::assertSame('Tony', $read['data']['display_name'] ?? null);
    }

    public function testPlainUserCannotReadOrUpdateAnotherUser(): void
    {
        $alice = $this->login('alice@example.com');
        $this->login('bob@example.com');
        $bob = $this->userId('bob@example.com');

        self::assertSame(403, $this->authedGet("/users/$bob", $alice['access'])->getStatusCode());
        self::assertSame(403, $this->authedPatch("/users/$bob", ['display_name' => 'Hacked'], $alice['access'])->getStatusCode());
        self::assertSame(403, $this->authedDelete("/users/$bob", $alice['access'])->getStatusCode());
    }

    public function testSuperadminCanReadAndUpdateAnyUser(): void
    {
        $admin = $this->superadmin();
        $this->login('target@example.com');
        $target = $this->userId('target@example.com');

        $read = $this->json($this->authedGet("/users/$target", $admin));
        self::assertSame('target@example.com', $read['data']['email'] ?? null);

        self::assertSame(200, $this->authedPatch("/users/$target", ['display_name' => 'Renamed'], $admin)->getStatusCode());
        self::assertSame('Renamed', $this->json($this->authedGet("/users/$target", $admin))['data']['display_name'] ?? null);
    }

    public function testDisableRevokesSessionsAndBlocksLogin(): void
    {
        $admin = $this->superadmin();
        $target = $this->login('target@example.com');
        $targetId = $this->userId('target@example.com');

        self::assertSame(200, $this->authedPostJson("/users/$targetId/disable", [], $admin)->getStatusCode());

        self::assertSame('disabled', $this->json($this->authedGet("/users/$targetId", $admin))['data']['status'] ?? null);
        // Existing sessions die immediately…
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $target['refresh']])->getStatusCode());
        // …and new logins are rejected.
        self::assertSame(403, $this->postJson('/auth/login', ['email' => 'target@example.com', 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testEnableRestoresAccess(): void
    {
        $admin = $this->superadmin();
        $this->login('target@example.com');
        $targetId = $this->userId('target@example.com');

        self::assertSame(200, $this->authedPostJson("/users/$targetId/disable", [], $admin)->getStatusCode());
        self::assertSame(200, $this->authedPostJson("/users/$targetId/enable", [], $admin)->getStatusCode());

        self::assertSame('active', $this->json($this->authedGet("/users/$targetId", $admin))['data']['status'] ?? null);
        self::assertSame(200, $this->postJson('/auth/login', ['email' => 'target@example.com', 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testAdminCannotDisableThemselves(): void
    {
        $admin = $this->superadmin();
        $adminId = $this->userId('operator@example.com');

        self::assertSame(409, $this->authedPostJson("/users/$adminId/disable", [], $admin)->getStatusCode());
    }

    public function testPlainUserLacksPermissionToDisableOrEnable(): void
    {
        $alice = $this->login('alice@example.com');
        $this->login('bob@example.com');
        $bob = $this->userId('bob@example.com');

        self::assertSame(403, $this->authedPostJson("/users/$bob/disable", [], $alice['access'])->getStatusCode());
        self::assertSame(403, $this->authedPostJson("/users/$bob/enable", [], $alice['access'])->getStatusCode());
        // Not even on themselves: disable/enable is admin tooling.
        $aliceId = $this->userId('alice@example.com');
        self::assertSame(403, $this->authedPostJson("/users/$aliceId/disable", [], $alice['access'])->getStatusCode());
    }

    public function testADisabledAdminsLiveTokenLosesAllAuthorityImmediately(): void
    {
        $admin = $this->superadmin();
        $second = $this->secondSuperadmin();
        $adminId = $this->userId('operator@example.com');

        self::assertSame(200, $this->authedPostJson("/users/$adminId/disable", [], $second)->getStatusCode());

        // The disabled admin's not-yet-expired token is now powerless on gated routes —
        // authority is re-resolved from the database per request — so they cannot re-enable
        // themselves or disable their disabler.
        $secondId = $this->userId('operator2@example.com');
        self::assertSame(403, $this->authedPostJson("/users/$adminId/enable", [], $admin)->getStatusCode());
        self::assertSame(403, $this->authedPostJson("/users/$secondId/disable", [], $admin)->getStatusCode());
    }

    public function testDisablingTwiceEmitsASingleEvent(): void
    {
        $admin = $this->superadmin();
        $this->login('target@example.com');
        $targetId = $this->userId('target@example.com');

        self::assertSame(200, $this->authedPostJson("/users/$targetId/disable", [], $admin)->getStatusCode());
        self::assertSame(200, $this->authedPostJson("/users/$targetId/disable", [], $admin)->getStatusCode());

        self::assertCount(1, $this->events->ofType(UserDisabled::class));
    }

    public function testATombstoneCannotBeReEnabled(): void
    {
        $admin = $this->superadmin();
        $this->login('target@example.com');
        $target = $this->userId('target@example.com');

        self::assertSame(200, $this->authedDelete("/users/$target", $admin)->getStatusCode());
        self::assertSame(409, $this->authedPostJson("/users/$target/enable", [], $admin)->getStatusCode());
    }

    public function testNonAdminProbingAnUnknownIdGetsForbiddenNotNotFound(): void
    {
        $alice = $this->login('alice@example.com');
        $unknown = Uuid::v7()->toRfc4122();

        // 403 before existence is consulted: a non-admin learns nothing about which ids exist.
        self::assertSame(403, $this->authedGet("/users/$unknown", $alice['access'])->getStatusCode());
        self::assertSame(403, $this->authedDelete("/users/$unknown", $alice['access'])->getStatusCode());
    }

    public function testSelfDeleteAnonymizesAndKillsTheAccount(): void
    {
        $admin = $this->superadmin();
        $session = $this->login('leaving@example.com');
        $id = $this->userId('leaving@example.com');

        self::assertSame(200, $this->authedDelete("/users/$id", $session['access'])->getStatusCode());

        // The row survives as a tombstone: anonymized email, nulled profile, disabled.
        $read = $this->json($this->authedGet("/users/$id", $admin));
        $email = (string) ($read['data']['email'] ?? '');
        self::assertStringNotContainsString('leaving@example.com', $email);
        self::assertTrue(str_contains($email, '@deleted.invalid'));
        self::assertArrayHasKey('display_name', $read['data'] ?? []);
        self::assertNull($read['data']['display_name']);
        self::assertSame('disabled', $read['data']['status'] ?? null);

        // Sessions are dead and the credentials are gone.
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $session['refresh']])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/login', ['email' => 'leaving@example.com', 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testAdminCanDeleteAUser(): void
    {
        $admin = $this->superadmin();
        $this->login('target@example.com');
        $target = $this->userId('target@example.com');

        self::assertSame(200, $this->authedDelete("/users/$target", $admin)->getStatusCode());
        $email = (string) ($this->json($this->authedGet("/users/$target", $admin))['data']['email'] ?? '');
        self::assertTrue(str_contains($email, '@deleted.invalid'));
    }

    public function testUnknownUserIsNotFoundForAdmins(): void
    {
        $admin = $this->superadmin();
        $unknown = Uuid::v7()->toRfc4122();

        self::assertSame(404, $this->authedGet("/users/$unknown", $admin)->getStatusCode());
        self::assertSame(404, $this->authedPatch("/users/$unknown", ['display_name' => 'X'], $admin)->getStatusCode());
        self::assertSame(404, $this->authedPostJson("/users/$unknown/disable", [], $admin)->getStatusCode());
        self::assertSame(404, $this->authedDelete("/users/$unknown", $admin)->getStatusCode());
    }

    public function testRejectsBadProfileInput(): void
    {
        $session = $this->login('me@example.com');
        $id = $this->userId('me@example.com');

        self::assertSame(422, $this->authedPatch("/users/$id", ['display_name' => str_repeat('x', 121)], $session['access'])->getStatusCode());
    }

    public function testRequiresAuthentication(): void
    {
        $id = Uuid::v7()->toRfc4122();

        self::assertSame(401, $this->get("/users/$id")->getStatusCode());
        self::assertSame(401, $this->postJson("/users/$id/disable", [])->getStatusCode());
    }

    // --- helpers ---

    /**
     * Logs in `operator@example.com`, gives them an org membership linked to the global
     * `superadmin` role, and returns their access token (the Gate re-resolves authority per
     * request, so the pre-link token works).
     */
    private function superadmin(): string
    {
        $session = $this->login('operator@example.com');
        $this->createOrg('Root', $session['access']);

        $membershipId = $this->idFrom('auth_memberships', ['user_id' => $this->userId('operator@example.com')]);
        $this->connection()->insert('auth_membership_roles')->values([
            'membership_id' => $membershipId,
            'role_id' => $this->systemRoleId('superadmin'),
        ])->run();

        return $session['access'];
    }

    /**
     * A second, independent superadmin (`operator2@example.com`).
     */
    private function secondSuperadmin(): string
    {
        $session = $this->login('operator2@example.com');
        $this->createOrg('Root Two', $session['access']);

        $membershipId = $this->idFrom('auth_memberships', ['user_id' => $this->userId('operator2@example.com')]);
        $this->connection()->insert('auth_membership_roles')->values([
            'membership_id' => $membershipId,
            'role_id' => $this->systemRoleId('superadmin'),
        ])->run();

        return $session['access'];
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

    private function userId(string $email): string
    {
        return $this->idFrom('auth_users', ['email' => $email]);
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
