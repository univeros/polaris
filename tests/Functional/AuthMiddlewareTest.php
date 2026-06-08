<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Univeros\Polaris\Event\UserRegistered;

/**
 * End-to-end tests for the wired auth pipeline (issue #15): the real
 * `TokenAuthenticationMiddleware` + `AuthRateLimitMiddleware` run in their production positions,
 * so these exercise the acceptance criteria directly — protected routes require a valid token,
 * public routes skip authentication, and over-budget requests get a `429`.
 */
final class AuthMiddlewareTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    public function testAPublicPathSkipsAuthentication(): void
    {
        // The JWKS document is public — no token, no challenge.
        self::assertSame(200, $this->get('/auth/.well-known/jwks.json')->getStatusCode());
    }

    public function testAProtectedPathWithoutATokenIsRejectedByTheMiddleware(): void
    {
        $response = $this->get('/auth/me');

        self::assertSame(401, $response->getStatusCode());
        // The `WWW-Authenticate` challenge is set by the middleware, proving the rejection
        // happened in the pipeline, before the domain ran.
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('unauthorized', $this->json($response)['error']);
    }

    public function testAProtectedPathWithAnInvalidBearerIsUnauthorized(): void
    {
        self::assertSame(401, $this->authedGet('/auth/me', 'not-a-real-jwt')->getStatusCode());
    }

    public function testEveryProtectedRouteIsRejectedByTheMiddlewareWithoutAToken(): void
    {
        // Each protected route, exercised with its real verb and no token. The `WWW-Authenticate`
        // header is set only by the middleware, so its presence proves the request was rejected in
        // the pipeline rather than by the domain — i.e. the route really is gated.
        $responses = [
            'GET /auth/me' => $this->get('/auth/me'),
            'GET /auth/sessions' => $this->get('/auth/sessions'),
            'POST /auth/logout' => $this->postJson('/auth/logout', []),
            'POST /auth/logout-all' => $this->postJson('/auth/logout-all', []),
            'POST /auth/password/change' => $this->postJson('/auth/password/change', []),
            'DELETE /auth/sessions/{id}' => $this->harness->handle(
                (new ServerRequestFactory())->createServerRequest('DELETE', '/auth/sessions/abc'),
            ),
        ];

        foreach ($responses as $route => $response) {
            self::assertSame(401, $response->getStatusCode(), "$route must require a token");
            self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'), "$route gated by the middleware");
        }
    }

    public function testAProtectedPathWithAValidBearerReachesTheDomain(): void
    {
        $this->register();
        $access = $this->login();

        $response = $this->authedGet('/auth/me', $access);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(self::EMAIL, $this->json($response)['data']['email']);
    }

    public function testLoginIsRateLimited(): void
    {
        // The default login budget is 10 per 5 minutes (security.md §5).
        for ($attempt = 0; $attempt < 10; ++$attempt) {
            $status = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong'])->getStatusCode();
            self::assertNotSame(429, $status, "request $attempt should be within budget");
        }

        $blocked = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);

        self::assertSame(429, $blocked->getStatusCode());
        self::assertSame('10', $blocked->getHeaderLine('X-RateLimit-Limit'));
        self::assertNotSame('', $blocked->getHeaderLine('Retry-After'));
    }

    private function register(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();
    }

    private function login(): string
    {
        $body = $this->json($this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]));
        self::assertIsArray($body['data']);

        return (string) ($body['data']['access_token'] ?? '');
    }
}
