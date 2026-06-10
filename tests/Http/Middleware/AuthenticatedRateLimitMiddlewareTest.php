<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Middleware\RateLimit\RateLimit;
use Altair\Http\Middleware\RateLimit\RateLimitMiddleware;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Http\Middleware\AuthenticatedRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\TokenSubjectKeyResolver;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Tests\Support\CountingRequestHandler;

/**
 * The global authenticated budget (issue #97): keyed on the token's `sub`, so it follows the
 * user across IPs, and a no-op on requests that carry no token.
 */
final class AuthenticatedRateLimitMiddlewareTest extends TestCase
{
    private AuthenticatedRateLimitMiddleware $middleware;
    private CountingRequestHandler $handler;

    protected function setUp(): void
    {
        $this->middleware = new AuthenticatedRateLimitMiddleware(
            new RateLimitMiddleware(
                new InMemoryCache(),
                new RateLimit(2, 60, 'auth.authenticated'),
                new ResponseFactory(),
                new TokenSubjectKeyResolver(),
            ),
        );
        $this->handler = new CountingRequestHandler();
    }

    public function testAnAuthenticatedUserIsBudgetedAcrossEndpoints(): void
    {
        self::assertSame(200, $this->middleware->process($this->authedRequest('user-1', '/auth/me'), $this->handler)->getStatusCode());
        self::assertSame(200, $this->middleware->process($this->authedRequest('user-1', '/orgs'), $this->handler)->getStatusCode());

        // The budget is global across authenticated endpoints, not per path.
        $blocked = $this->middleware->process($this->authedRequest('user-1', '/auth/sessions'), $this->handler);
        self::assertSame(429, $blocked->getStatusCode());
        self::assertNotSame('', $blocked->getHeaderLine('Retry-After'));
        self::assertSame(2, $this->handler->calls, 'the blocked request never reaches the handler');
    }

    public function testTheBudgetIsPerUserNotPerIp(): void
    {
        $this->middleware->process($this->authedRequest('user-1', '/auth/me'), $this->handler);
        $this->middleware->process($this->authedRequest('user-1', '/auth/me'), $this->handler);
        self::assertSame(429, $this->middleware->process($this->authedRequest('user-1', '/auth/me'), $this->handler)->getStatusCode());

        // Another user is unaffected by the first user's exhausted budget.
        self::assertSame(200, $this->middleware->process($this->authedRequest('user-2', '/auth/me'), $this->handler)->getStatusCode());
    }

    public function testARequestWithoutATokenPassesThroughUntouched(): void
    {
        $response = $this->middleware->process($this->request('/auth/login'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('X-RateLimit-Limit'), 'unauthenticated requests get no limiter headers');
        self::assertSame(1, $this->handler->calls);
    }

    private function authedRequest(string $subject, string $path): ServerRequestInterface
    {
        $token = self::createStub(TokenInterface::class);
        $token->method('getMetadata')->willReturnCallback(
            static fn(string $key): ?string => $key === 'sub' ? $subject : null,
        );

        return $this->request($path)->withAttribute(TokenInterface::TOKEN_KEY, $token);
    }

    private function request(string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('GET', $path);
    }
}
