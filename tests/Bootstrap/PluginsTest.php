<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Bootstrap;

use Altair\Container\Container;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use LogicException;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Exception\InvalidConfigException;
use Polaris\Schema\Schema;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Username\UsernamePlugin;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Http\PolarisMiddleware;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\ArrayEnv;
use Univeros\Polaris\Tests\Support\HeaderPlugin;
use Univeros\Polaris\Tests\Support\TestPolaris;

use function array_column;
use function json_encode;

final class PluginsTest extends TestCase
{
    public function testWithoutConfigurationPolarisRunsWithNoPlugin(): void
    {
        $config = PolarisConfig::fromContainer(self::container(), new ArrayEnv([]));

        self::assertSame([], $config->plugins);
    }

    public function testTheBoundPluginsAreHandedToPolarisInOrder(): void
    {
        $username = new UsernamePlugin();
        $header = new HeaderPlugin();
        $container = self::container();
        $container->instance(Plugins::class, new Plugins($username, $header));

        $config = PolarisConfig::fromContainer($container, new ArrayEnv([]));

        self::assertSame([$username, $header], $config->plugins);
    }

    public function testPolarisPluginsNamesPluginClassesBuiltThroughTheContainer(): void
    {
        $env = new ArrayEnv(['POLARIS_PLUGINS' => ' ' . UsernamePlugin::class . ' , ' . HeaderPlugin::class . ',']);

        $config = PolarisConfig::fromContainer(self::container(), $env);

        self::assertCount(2, $config->plugins);
        self::assertInstanceOf(UsernamePlugin::class, $config->plugins[0]);
        self::assertInstanceOf(HeaderPlugin::class, $config->plugins[1]);
    }

    public function testTheBindingWinsOverTheEnvironment(): void
    {
        $header = new HeaderPlugin();
        $container = self::container();
        $container->instance(Plugins::class, new Plugins($header));

        $config = PolarisConfig::fromContainer($container, new ArrayEnv(['POLARIS_PLUGINS' => UsernamePlugin::class]));

        self::assertSame([$header], $config->plugins);
    }

    public function testAnUnknownClassFailsBootNamingIt(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('App\\Missing\\Plugin');

        PolarisConfig::fromContainer(self::container(), new ArrayEnv(['POLARIS_PLUGINS' => 'App\\Missing\\Plugin']));
    }

    public function testAClassThatIsNotAPluginFailsBootNamingIt(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('stdClass');

        PolarisConfig::fromContainer(self::container(), new ArrayEnv(['POLARIS_PLUGINS' => stdClass::class]));
    }

    public function testAPluginsRoutesTablesMiddlewareAndPermissionsReachTheHost(): void
    {
        $container = TestPolaris::boot([Plugins::class => new Plugins(new UsernamePlugin(), new HeaderPlugin())]);
        $middleware = $container->get(PolarisMiddleware::class);
        \assert($middleware instanceof PolarisMiddleware);

        $response = $middleware->process(self::signIn(), self::framework());

        self::assertSame(401, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('on', $response->getHeaderLine(HeaderPlugin::HEADER));
        self::assertArrayHasKey(HeaderPlugin::PERMISSION, TestPolaris::graph($container)->permissionCatalog()->permissions());
        self::assertContains('polaris_username', array_column(Schema::all(), 'table'));
    }

    private static function container(): Container
    {
        $container = new Container();
        $container->instance(Secrets::class, TestPolaris::secrets());
        $container->instance(AuthConfig::class, TestPolaris::auth());
        $container->instance(DatabaseAdapter::class, new InMemoryAdapter());

        return $container;
    }

    private static function signIn(): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('POST', '/username/sign-in')
            ->withHeader('Content-Type', 'application/json')
            ->withBody((new StreamFactory())->createStream((string) json_encode(['username' => 'nobody', 'password' => 'wrong-password'])))
            ->withParsedBody([]);
    }

    private static function framework(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new LogicException('A plugin route must not reach the framework.');
            }
        };
    }
}
