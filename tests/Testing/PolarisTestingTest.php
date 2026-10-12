<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Testing;

use Altair\Container\Container;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Module\ModuleConfiguration;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Authorization\Gate;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Testing\InMemoryAdapter;
use Univeros\Polaris\Module;
use Univeros\Polaris\Testing\PolarisTesting;
use Univeros\Polaris\Tests\Support\RecordingHandler;
use Univeros\Polaris\Token\DualToken;

final class PolarisTestingTest extends TestCase
{
    public function testAHostTestBootsPolarisInMemoryAndActsAsAUser(): void
    {
        $container = new Container();
        PolarisTesting::bind($container);
        (new ModuleConfiguration([new Module()]))->apply($container);
        $middleware = $container->get(TokenAuthenticationMiddleware::class);
        \assert($middleware instanceof TokenAuthenticationMiddleware);
        $handler = new RecordingHandler();

        $token = PolarisTesting::token($container, 'user-7', organizationId: 'org-1', roles: ['admin']);
        $response = $middleware->process(
            (new ServerRequestFactory())->createServerRequest('GET', 'http://api.example.com/app/me')->withHeader('Authorization', 'Bearer ' . $token),
            $handler,
        );

        self::assertInstanceOf(InMemoryAdapter::class, $container->get(DatabaseAdapter::class));
        self::assertSame(200, $response->getStatusCode());
        $seen = $handler->token();
        self::assertInstanceOf(DualToken::class, $seen);
        self::assertSame('user-7', $seen->getMetadata('sub'));
        self::assertSame('org-1', $seen->getMetadata('org'));
        self::assertSame(['admin'], $seen->getMetadata('roles'));
    }

    public function testADelegatedTokenCarriesItsPermissionSubset(): void
    {
        $container = new Container();
        PolarisTesting::bind($container);
        (new ModuleConfiguration([new Module()]))->apply($container);
        $middleware = $container->get(TokenAuthenticationMiddleware::class);
        \assert($middleware instanceof TokenAuthenticationMiddleware);
        $handler = new RecordingHandler();

        $token = PolarisTesting::token($container, 'user-7', delegated: ['invoices.read']);
        $middleware->process(
            (new ServerRequestFactory())->createServerRequest('GET', 'http://api.example.com/app/me')->withHeader('Authorization', 'Bearer ' . $token),
            $handler,
        );

        $seen = $handler->token();
        self::assertInstanceOf(DualToken::class, $seen);
        self::assertSame(['invoices.read'], $seen->getMetadata(Gate::DELEGATED));
    }

    public function testWhatTheHostBindsFirstWins(): void
    {
        $database = new InMemoryAdapter();
        $container = new Container();
        $container->instance(DatabaseAdapter::class, $database);

        PolarisTesting::bind($container);

        self::assertSame($database, $container->get(DatabaseAdapter::class));
    }
}
