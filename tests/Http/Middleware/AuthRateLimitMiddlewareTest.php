<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Altair\Http\Middleware\RateLimit\IpKeyResolver;
use Altair\Http\Middleware\RateLimit\RateLimit;
use Altair\Http\Middleware\RateLimit\RateLimitMiddleware;
use Altair\Http\Rule\RequestPathRule;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Http\Middleware\AuthRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\RateLimitGroup;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Tests\Support\CountingRequestHandler;

final class AuthRateLimitMiddlewareTest extends TestCase
{
    private InMemoryCache $cache;
    private CountingRequestHandler $handler;

    protected function setUp(): void
    {
        $this->cache = new InMemoryCache();
        $this->handler = new CountingRequestHandler();
    }

    public function testUnderTheLimitPassesThroughWithRateLimitHeaders(): void
    {
        $middleware = $this->middleware();

        $response = $middleware->process($this->request('/auth/login'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('2', $response->getHeaderLine('X-RateLimit-Limit'));
        self::assertSame('1', $response->getHeaderLine('X-RateLimit-Remaining'));
        self::assertSame(1, $this->handler->calls);
    }

    public function testAtTheLimitReturns429AndDoesNotCallTheHandler(): void
    {
        $middleware = $this->middleware();

        $middleware->process($this->request('/auth/login'), $this->handler); // 1/2
        $middleware->process($this->request('/auth/login'), $this->handler); // 2/2
        $blocked = $middleware->process($this->request('/auth/login'), $this->handler); // over

        self::assertSame(429, $blocked->getStatusCode());
        self::assertNotSame('', $blocked->getHeaderLine('Retry-After'));
        self::assertSame('0', $blocked->getHeaderLine('X-RateLimit-Remaining'));
        self::assertSame(2, $this->handler->calls, 'the blocked request never reaches the handler');
    }

    public function testANonMatchingPathPassesThroughUntouched(): void
    {
        $middleware = $this->middleware();

        $response = $middleware->process($this->request('/auth/me'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('X-RateLimit-Limit'), 'unlimited paths get no limiter headers');
        self::assertSame(1, $this->handler->calls);
    }

    public function testGroupsAreCountedIndependently(): void
    {
        $middleware = $this->middleware();

        // Exhaust the login budget…
        $middleware->process($this->request('/auth/login'), $this->handler);
        $middleware->process($this->request('/auth/login'), $this->handler);
        self::assertSame(429, $middleware->process($this->request('/auth/login'), $this->handler)->getStatusCode());

        // …the register budget is untouched.
        self::assertSame(200, $middleware->process($this->request('/auth/register'), $this->handler)->getStatusCode());
    }

    private function middleware(): AuthRateLimitMiddleware
    {
        $responseFactory = new ResponseFactory();
        $keyResolver = new IpKeyResolver();

        return new AuthRateLimitMiddleware(
            new RateLimitGroup(
                new RequestPathRule(['path' => ['/auth/login']]),
                new RateLimitMiddleware($this->cache, new RateLimit(2, 60, 'auth.login'), $responseFactory, $keyResolver),
            ),
            new RateLimitGroup(
                new RequestPathRule(['path' => ['/auth/register']]),
                new RateLimitMiddleware($this->cache, new RateLimit(5, 60, 'auth.register'), $responseFactory, $keyResolver),
            ),
        );
    }

    private function request(string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('POST', $path);
    }
}
