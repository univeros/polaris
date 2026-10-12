<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Introspection;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Http\Collection\RouteCollection;
use Altair\Introspection\Inspector\RouteInspector;
use PHPUnit\Framework\TestCase;
use Polaris\Username\UsernamePlugin;
use Univeros\Polaris\Module;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\ArrayEnv;

use function array_column;

final class RouteInspectorTest extends TestCase
{
    public function testTheRoutesListShowsThePolarisAndPluginRoutesBesideTheHosts(): void
    {
        $routes = new RouteCollection(['GET /app/me' => 'App\\Me']);
        $container = new Container();
        $container->instance(RouteCollection::class, $routes);
        // As IntrospectionConfiguration binds it, before the modules apply.
        $container->factory(RouteInspector::class, static fn(RouteCollection $routes): RouteInspector => new RouteInspector($routes))->shared();
        $container->instance(Env::class, new ArrayEnv(['POLARIS_PATH_PREFIX' => '/auth']));
        $container->instance(Plugins::class, new Plugins(new UsernamePlugin()));
        (new Module())->apply($container);

        $inspector = $container->get(RouteInspector::class);
        \assert($inspector instanceof RouteInspector);
        $rows = $inspector->inspectAll()->rows;
        $listed = array_column($rows, 'action', 'path');

        self::assertSame('App\\Me', $listed['/app/me']);
        self::assertArrayHasKey('/auth/auth/login', $listed);
        self::assertStringStartsWith('Polaris\\', $listed['/auth/auth/login']);
        self::assertArrayHasKey('/auth/username/sign-in', $listed);
        self::assertCount(1, $routes, 'the dispatch table is untouched');
    }
}
