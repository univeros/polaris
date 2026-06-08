<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Altair\Http\Contracts\TokenParserInterface;
use Psr\Http\Message\ResponseInterface;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\SessionsRevoked;
use Univeros\Polaris\Event\UserRegistered;

use function array_filter;
use function array_values;

/**
 * End-to-end tests for the refresh and session-management endpoints. Protected endpoints
 * are exercised with the access token attached as the auth middleware (#15) would.
 */
final class SessionEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    public function testRefreshRotatesAndDetectsReuseOfTheOldToken(): void
    {
        $this->register();
        $session = $this->login();

        $rotated = $this->pair($this->postJson('/auth/token/refresh', ['refresh_token' => $session['refresh']]));
        self::assertNotSame($session['refresh'], $rotated['refresh']);
        self::assertNotSame('', $rotated['access']);

        // Replaying the original (now-rotated) refresh token is rejected.
        $this->unitOfWork->clear();
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $session['refresh']])->getStatusCode());
    }

    public function testRefreshRejectsUnknownTokenAndRequiresInput(): void
    {
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => 'not-a-token'])->getStatusCode());
        self::assertSame(422, $this->postJson('/auth/token/refresh', [])->getStatusCode());
    }

    public function testSessionsListFlagsTheCallingSession(): void
    {
        $this->register();
        $first = $this->login();
        $this->login(); // a second device/session for the same user

        $sessions = $this->sessionsOf($first['access']);
        self::assertCount(2, $sessions);

        $current = array_values(array_filter($sessions, static fn(array $s): bool => $s['current'] === true));
        self::assertCount(1, $current, 'exactly one session is flagged current');
        self::assertSame($this->sidOf($first['access']), $current[0]['id']);
    }

    public function testLogoutRevokesTheCurrentSession(): void
    {
        $this->register();
        $session = $this->login();

        self::assertSame(200, $this->authedPostJson('/auth/logout', [], $session['access'])->getStatusCode());

        // The session's refresh token can no longer be exchanged.
        $this->unitOfWork->clear();
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $session['refresh']])->getStatusCode());

        // A post-logout refresh is an ended session, not theft — no reuse alert fires.
        self::assertCount(0, $this->events->ofType(RefreshReuseDetected::class));
    }

    public function testLogoutAllRevokesEverySession(): void
    {
        $this->register();
        $first = $this->login();
        $second = $this->login();

        self::assertSame(200, $this->authedPostJson('/auth/logout-all', [], $first['access'])->getStatusCode());
        self::assertCount(1, $this->events->ofType(SessionsRevoked::class));

        $this->unitOfWork->clear();
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $first['refresh']])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $second['refresh']])->getStatusCode());
    }

    public function testRevokeASpecificSession(): void
    {
        $this->register();
        $keep = $this->login();
        $drop = $this->login();
        $dropSid = $this->sidOf($drop['access']);

        self::assertSame(200, $this->authedDelete('/auth/sessions/' . $dropSid, $keep['access'])->getStatusCode());

        $this->unitOfWork->clear();
        // The revoked session is dead; the caller's own session still refreshes.
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $drop['refresh']])->getStatusCode());
        self::assertSame(200, $this->postJson('/auth/token/refresh', ['refresh_token' => $keep['refresh']])->getStatusCode());
    }

    public function testRevokingAnUnknownSessionIsNotFound(): void
    {
        $this->register();
        $session = $this->login();

        self::assertSame(404, $this->authedDelete('/auth/sessions/no-such-family', $session['access'])->getStatusCode());
    }

    public function testProtectedEndpointsRequireAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/auth/logout', [])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/logout-all', [])->getStatusCode());
        self::assertSame(401, $this->get('/auth/sessions')->getStatusCode());
    }

    private function register(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();
    }

    /**
     * @return array{access: string, refresh: string}
     */
    private function login(): array
    {
        return $this->pair($this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]));
    }

    /**
     * @return array{access: string, refresh: string}
     */
    private function pair(ResponseInterface $response): array
    {
        $body = $this->json($response);
        self::assertIsArray($body['data']);
        $data = $body['data'];

        return [
            'access' => (string) ($data['access_token'] ?? ''),
            'refresh' => (string) ($data['refresh_token'] ?? ''),
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function sessionsOf(string $accessToken): array
    {
        $body = $this->json($this->authedGet('/auth/sessions', $accessToken));
        self::assertIsArray($body['data']);
        self::assertIsArray($body['data']['sessions']);
        /** @var list<array<string, mixed>> $sessions */
        $sessions = $body['data']['sessions'];

        return $sessions;
    }

    private function sidOf(string $accessToken): string
    {
        $parser = $this->container->get(TokenParserInterface::class);
        self::assertInstanceOf(TokenParserInterface::class, $parser);

        return (string) $parser->parse($accessToken)->getMetadata('sid');
    }
}
