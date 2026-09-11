<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Container\Container;
use Altair\Module\ModuleConfiguration;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\AccessTokenClaims;
use Polaris\Wiring\Graph;
use Univeros\Polaris\Module;

/**
 * The module booted the way a host boots it: the test's instances bound first, then
 * `ModuleConfiguration([new Module()])`. Secrets, auth settings and an in-memory database are
 * provided unless the test binds its own.
 */
final class TestPolaris
{
    public const string APP_KEY = 'app-key-for-univeros-polaris-tests-0123';
    public const string ISSUER = 'https://auth.polaris.test';

    public static function secrets(): Secrets
    {
        $keys = TestKeys::rsa();

        return Secrets::fromEnvironment([
            'APP_KEY' => self::APP_KEY,
            'AUTH_JWT_PRIVATE_KEY' => $keys['private'],
            'AUTH_JWT_PUBLIC_KEY' => $keys['public'],
        ]);
    }

    public static function auth(): AuthConfig
    {
        return AuthConfig::fromArray(['issuer' => self::ISSUER]);
    }

    /**
     * @param array<class-string, object> $instances bound before the module applies
     */
    public static function boot(array $instances = []): Container
    {
        $container = new Container();
        $instances += [
            DatabaseAdapter::class => new InMemoryAdapter(),
            Secrets::class => self::secrets(),
            AuthConfig::class => self::auth(),
        ];
        foreach ($instances as $id => $instance) {
            $container->instance($id, $instance);
        }
        (new ModuleConfiguration([new Module()]))->apply($container);

        return $container;
    }

    public static function graph(Container $container): Graph
    {
        $graph = $container->get(Graph::class);
        \assert($graph instanceof Graph);

        return $graph;
    }

    /**
     * An access token signed by the graph's keys, as `POST /auth/login` would mint one.
     */
    public static function accessToken(Graph $graph, string $subject = 'user-1'): string
    {
        return $graph->tokenGenerator()->generate((new AccessTokenClaims(subject: $subject, jwtId: 'jti-' . $subject))->toClaims());
    }
}
