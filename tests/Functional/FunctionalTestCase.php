<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Altair\Container\Container;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Cycle\ORM\ORMInterface;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Module;
use Univeros\Polaris\Tests\Functional\Support\ModuleHarness;
use Univeros\Polaris\Tests\Persistence\DatabaseTestCase;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\TestKeys;

use function is_array;
use function json_decode;
use function putenv;

/**
 * Base class for functional tests that drive Polaris HTTP endpoints end to end.
 *
 * It boots the real {@see Module} in a container over the same live database driver as the
 * persistence tests (so it is skipped when no driver is configured), with a real RSA
 * signing keypair and a {@see RecordingEventDispatcher} bound *before* the module applies —
 * so domain events (e.g. the verification token carried on `user.registered`) are
 * capturable. Requests are sent through the {@see ModuleHarness}.
 */
abstract class FunctionalTestCase extends DatabaseTestCase
{
    protected Container $container;
    protected ModuleHarness $harness;
    protected RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        parent::setUp();

        $keys = TestKeys::rsa();
        putenv('APP_KEY=app-key-for-functional-tests');
        putenv('AUTH_JWT_PRIVATE_KEY=' . $keys['private']);
        putenv('AUTH_JWT_PUBLIC_KEY=' . $keys['public']);
        putenv('AUTH_ISSUER=https://auth.polaris.test');

        $this->events = new RecordingEventDispatcher();

        $container = new Container();
        $container->instance(ORMInterface::class, $this->orm);
        $container->instance(UnitOfWorkInterface::class, $this->unitOfWork);
        $container->instance(EventDispatcherInterface::class, $this->events);
        $container->instance(ResponseFactoryInterface::class, new ResponseFactory());

        $module = new Module();
        $module->apply($container);

        $this->container = $container;
        $this->harness = new ModuleHarness($container, $module->routes());
    }

    protected function tearDown(): void
    {
        foreach (['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_ISSUER', 'AUTH_AUDIENCE', 'AUTH_JWT_KID'] as $key) {
            putenv($key);
        }

        parent::tearDown();
    }

    protected function get(string $path): ResponseInterface
    {
        return $this->harness->handle((new ServerRequestFactory())->createServerRequest('GET', $path));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function postJson(string $path, array $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->harness->handle($request);
    }

    protected function authedGet(string $path, string $accessToken): ResponseInterface
    {
        return $this->harness->handle($this->withToken(
            (new ServerRequestFactory())->createServerRequest('GET', $path),
            $accessToken,
        ));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function authedPostJson(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->harness->handle($this->withToken($request, $accessToken));
    }

    protected function authedDelete(string $path, string $accessToken): ResponseInterface
    {
        return $this->harness->handle($this->withToken(
            (new ServerRequestFactory())->createServerRequest('DELETE', $path),
            $accessToken,
        ));
    }

    /**
     * Attaches the parsed access token as the request attribute the
     * `TokenAuthenticationMiddleware` (issue #15) would set, so protected domains see an
     * authenticated request.
     */
    private function withToken(ServerRequestInterface $request, string $accessToken): ServerRequestInterface
    {
        $parser = $this->container->get(TokenParserInterface::class);
        self::assertInstanceOf(TokenParserInterface::class, $parser);

        return $request->withAttribute(TokenInterface::TOKEN_KEY, $parser->parse($accessToken));
    }

    /**
     * @return array<string, mixed>
     */
    protected function json(ResponseInterface $response): array
    {
        $body = (string) $response->getBody();
        $decoded = $body === '' ? [] : json_decode($body, true);

        return is_array($decoded) ? $decoded : [];
    }
}
