<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function base64_decode;
use function explode;
use function is_array;
use function is_string;
use function json_decode;
use function strtr;

/**
 * Drives the #35 `POST /auth/switch-org` flow end to end: switching re-scopes the access token to
 * the chosen org (embedding its `org` + `roles`), the re-scoping persists through a refresh, and a
 * caller cannot switch to an org they are not an active member of.
 */
final class OrgSwitchEndpointTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testSwitchReScopesTheAccessTokenToTheChosenOrg(): void
    {
        ['access' => $access] = $this->login('founder@example.com');

        // Right after login there is no active org.
        self::assertNull($this->claimsOf($access)['org'] ?? null);
        self::assertSame([], $this->claimsOf($access)['roles'] ?? null);

        $acme = $this->createOrg('Acme', $access);
        $globex = $this->createOrg('Globex', $access);

        $switched = $this->json($this->authedPostJson('/auth/switch-org', ['organization_id' => $acme], $access));
        self::assertSame($acme, $switched['data']['org'] ?? null);
        $acmeClaims = $this->claimsOf((string) ($switched['data']['access_token'] ?? ''));
        self::assertSame($acme, $acmeClaims['org'] ?? null);
        self::assertSame(['owner'], $acmeClaims['roles'] ?? null);

        $toGlobex = $this->json($this->authedPostJson('/auth/switch-org', ['organization_id' => $globex], $access));
        self::assertSame($globex, $this->claimsOf((string) ($toGlobex['data']['access_token'] ?? ''))['org'] ?? null);
    }

    public function testSwitchedOrgPersistsThroughRefresh(): void
    {
        ['access' => $access, 'refresh' => $refresh] = $this->login('founder@example.com');
        $acme = $this->createOrg('Acme', $access);

        self::assertSame(200, $this->authedPostJson('/auth/switch-org', ['organization_id' => $acme], $access)->getStatusCode());

        // The session's org context was re-pointed, so a refresh re-resolves the same org + roles.
        $refreshed = $this->json($this->postJson('/auth/token/refresh', ['refresh_token' => $refresh]));
        $claims = $this->claimsOf((string) ($refreshed['data']['access_token'] ?? ''));
        self::assertSame($acme, $claims['org'] ?? null);
        self::assertSame(['owner'], $claims['roles'] ?? null);
    }

    public function testCannotSwitchToAnOrgYouDoNotBelongTo(): void
    {
        ['access' => $founder] = $this->login('founder@example.com');
        $acme = $this->createOrg('Acme', $founder);

        ['access' => $outsider] = $this->login('outsider@example.com');
        $response = $this->authedPostJson('/auth/switch-org', ['organization_id' => $acme], $outsider);
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('forbidden', $this->json($response)['error'] ?? null);
    }

    public function testUnknownOrgIsRejected(): void
    {
        ['access' => $access] = $this->login('founder@example.com');

        $response = $this->authedPostJson('/auth/switch-org', ['organization_id' => Uuid::v7()->toRfc4122()], $access);
        self::assertSame(404, $response->getStatusCode());
    }

    public function testOrganizationIdIsRequired(): void
    {
        ['access' => $access] = $this->login('founder@example.com');

        self::assertSame(422, $this->authedPostJson('/auth/switch-org', [], $access)->getStatusCode());
    }

    public function testRequiresAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/auth/switch-org', ['organization_id' => Uuid::v7()->toRfc4122()])->getStatusCode());
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
