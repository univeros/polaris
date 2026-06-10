<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function base64_decode;
use function explode;
use function is_array;
use function is_string;
use function json_decode;
use function strtr;

/**
 * Exercises the #36 enforcement end to end on `GET /orgs/{id}` (which the AuthorizationMiddleware
 * gates on `org.read`): a member reads their active org, **cross-tenant access is denied** (a token
 * scoped to org A cannot read org B, even when the caller belongs to B), an inactive-org token is
 * denied, an unauthenticated request is rejected, and a `superadmin` may read any org.
 */
final class AuthorizationEnforcementTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testMemberCanReadTheirActiveOrganization(): void
    {
        ['access' => $access] = $this->login('founder@example.com');
        $org = $this->createOrg('Acme', $access);
        $scoped = $this->switchOrg($access, $org);

        $response = $this->authedGet("/orgs/$org", $scoped);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame($org, $this->json($response)['data']['id'] ?? null);
    }

    public function testCannotReadAnOrganizationOutsideTheActiveOne(): void
    {
        ['access' => $access] = $this->login('founder@example.com');
        $acme = $this->createOrg('Acme', $access);
        $globex = $this->createOrg('Globex', $access); // the caller owns this one too…
        $scopedToAcme = $this->switchOrg($access, $acme);

        // …but the active org is Acme, so reading Globex is forbidden (cross-tenant isolation).
        $response = $this->authedGet("/orgs/$globex", $scopedToAcme);
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('forbidden', $this->json($response)['error'] ?? null);
    }

    public function testCannotReadWithoutAnActiveOrg(): void
    {
        ['access' => $access] = $this->login('founder@example.com');
        $org = $this->createOrg('Acme', $access);

        // The login token carries no active org → no org.read → the middleware denies it.
        self::assertSame(403, $this->authedGet("/orgs/$org", $access)->getStatusCode());
    }

    public function testUnauthenticatedIsRejected(): void
    {
        self::assertSame(401, $this->get('/orgs/01910000-0000-7000-8000-0000000000aa')->getStatusCode());
    }

    public function testSuperadminCanReadAnyOrganization(): void
    {
        ['access' => $founder] = $this->login('founder@example.com');
        $acme = $this->createOrg('Acme', $founder);

        ['access' => $operator] = $this->login('operator@example.com');
        $ownOrg = $this->createOrg('Operations', $operator);
        $this->grantSuperadmin($this->userId('operator@example.com'), $ownOrg);

        // After re-scoping, the operator's token carries the superadmin override and reads Acme,
        // an org they are not a member of.
        $scoped = $this->switchOrg($operator, $ownOrg);
        self::assertSame(['superadmin'], $this->claimsOf($scoped)['roles'] ?? null);

        $response = $this->authedGet("/orgs/$acme", $scoped);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame($acme, $this->json($response)['data']['id'] ?? null);
    }

    /**
     * @return array{access: string, refresh: string}
     */
    private function login(string $email): array
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $token = $registered[array_key_last($registered)]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

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

    private function grantSuperadmin(string $userId, string $organizationId): void
    {
        $this->connection()->insert('auth_membership_roles')->values([
            'membership_id' => $this->idFrom('auth_memberships', ['user_id' => $userId, 'organization_id' => $organizationId]),
            'role_id' => $this->idFrom('auth_roles', ['slug' => 'superadmin']),
        ])->run();
    }

    private function userId(string $email): string
    {
        return $this->idFrom('auth_users', ['email' => $email]);
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

    /**
     * @return array<string, mixed>
     */
    private function claimsOf(string $jwt): array
    {
        $segment = explode('.', $jwt)[1] ?? '';
        $json = base64_decode(strtr($segment, '-_', '+/'), true);
        $decoded = $json === false ? [] : json_decode($json, true);

        return is_array($decoded) ? $decoded : [];
    }
}
