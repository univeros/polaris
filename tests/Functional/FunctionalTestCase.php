<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Altair\Container\Container;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Tests\Support\RecordingOtpMailer;
use Univeros\Polaris\Tests\Support\RecordingSmsSender;
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
    protected RecordingSmsSender $sms;
    protected RecordingOtpMailer $mailer;

    protected function setUp(): void
    {
        parent::setUp();

        $keys = TestKeys::rsa();
        putenv('APP_KEY=app-key-for-functional-tests');
        putenv('AUTH_JWT_PRIVATE_KEY=' . $keys['private']);
        putenv('AUTH_JWT_PUBLIC_KEY=' . $keys['public']);
        putenv('AUTH_ISSUER=https://auth.polaris.test');

        $this->events = new RecordingEventDispatcher();
        $this->sms = new RecordingSmsSender();
        $this->mailer = new RecordingOtpMailer();

        $container = new Container();
        $container->instance(ORMInterface::class, $this->orm);
        $container->instance(UnitOfWorkInterface::class, $this->unitOfWork);
        $container->instance(EventDispatcherInterface::class, $this->events);
        $container->instance(ResponseFactoryInterface::class, new ResponseFactory());
        // Recording OTP senders so functional tests can read the delivered code; the module binds
        // its Log* defaults only when absent, so these are preserved.
        $container->instance(SmsSenderInterface::class, $this->sms);
        $container->instance(OtpMailerInterface::class, $this->mailer);

        $module = new Module();
        $module->apply($container);

        $this->container = $container;
        $this->harness = new ModuleHarness($container, $module);
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

    /**
     * @param array<string, mixed> $body
     */
    protected function authedPatch(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('PATCH', $path)
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
     * Sends the access token as a real `Authorization: Bearer` header, so the wired
     * `TokenAuthenticationMiddleware` parses it and attaches the token the protected domains
     * read — the same path a production client takes.
     */
    private function withToken(ServerRequestInterface $request, string $accessToken): ServerRequestInterface
    {
        return $request->withHeader('Authorization', 'Bearer ' . $accessToken);
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
