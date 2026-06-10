<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Univeros\Polaris\Event\UserRegistered;

use function array_key_last;
use function putenv;

/**
 * Drives the #41 instant access-token revocation end to end: with
 * `AUTH_ACCESS_TOKEN_DENYLIST=1`, a logout-everywhere makes the not-yet-expired access token die
 * on the very next request instead of riding out its TTL. Off by default: without the flag the
 * stateless behavior is unchanged.
 */
final class DenylistEndpointsTest extends FunctionalTestCase
{
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testLogoutEverywhereKillsTheLiveAccessTokenInstantly(): void
    {
        putenv('AUTH_ACCESS_TOKEN_DENYLIST=1');
        $this->setUp();

        $access = $this->login('victim@example.com');
        self::assertSame(200, $this->authedGet('/auth/me', $access)->getStatusCode());

        self::assertSame(200, $this->authedPostJson('/auth/logout-all', [], $access)->getStatusCode());

        $response = $this->authedGet('/auth/me', $access);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('session_ended', $this->json($response)['error'] ?? null);
    }

    public function testWithoutTheFlagTheStatelessDefaultIsUnchanged(): void
    {
        $access = $this->login('victim@example.com');

        self::assertSame(200, $this->authedPostJson('/auth/logout-all', [], $access)->getStatusCode());

        // The access token rides out its TTL; only the refresh path is dead.
        self::assertSame(200, $this->authedGet('/auth/me', $access)->getStatusCode());
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
}
