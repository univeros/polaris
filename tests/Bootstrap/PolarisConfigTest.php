<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Bootstrap;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Persistence\Configuration\DatabaseSettings;
use Altair\Persistence\Exception\InvalidConfigurationException;
use Laminas\Diactoros\ResponseFactory;
use PDO;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Dialect;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Event\UserRegistered;
use Polaris\Pdo\PdoAdapter;
use Polaris\Support\InMemoryCache;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\RecordingLogger;
use Polaris\Tests\Support\RecordingOtpMailer;
use Polaris\Tests\Support\RecordingSmsSender;
use Polaris\Tests\Support\TestKeys;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Event\ListenerDispatcher;
use Univeros\Polaris\Tests\Support\TestPolaris;

use function putenv;
use function trim;

final class PolarisConfigTest extends TestCase
{
    private const array ENV = ['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_ISSUER', 'AUTH_AUDIENCE', 'AUTH_ACCESS_TOKEN_DENYLIST', 'AUTH_PASSWORD_BREACH_CHECK', 'POLARIS_PATH_PREFIX', 'POLARIS_DSN', 'DB_CONNECTION', 'DB_DATABASE'];

    protected function tearDown(): void
    {
        foreach (self::ENV as $key) {
            putenv($key);
        }
    }

    public function testEveryPortBoundBeforeTheModuleAppliesWins(): void
    {
        $ports = [
            Secrets::class => TestPolaris::secrets(),
            AuthConfig::class => TestPolaris::auth(),
            DatabaseAdapter::class => new InMemoryAdapter(),
            OtpMailerInterface::class => new RecordingOtpMailer(),
            SmsSenderInterface::class => new RecordingSmsSender(),
            CacheInterface::class => new InMemoryCache(),
            ClockInterface::class => FrozenClock::at('2026-09-11 10:00:00'),
            EventDispatcherInterface::class => new RecordingEventDispatcher(),
            LoggerInterface::class => new RecordingLogger(),
            RateLimitConfig::class => RateLimitConfig::defaults(),
            ResponseFactoryInterface::class => new ResponseFactory(),
        ];
        $container = new Container();
        foreach ($ports as $id => $instance) {
            $container->instance($id, $instance);
        }

        $config = PolarisConfig::fromContainer($container, new Env());

        self::assertSame($ports[Secrets::class], $config->secrets);
        self::assertSame($ports[AuthConfig::class], $config->auth);
        self::assertSame($ports[DatabaseAdapter::class], $config->database);
        self::assertSame($ports[OtpMailerInterface::class], $config->mailer);
        self::assertSame($ports[SmsSenderInterface::class], $config->sms);
        self::assertSame($ports[CacheInterface::class], $config->cache);
        self::assertSame($ports[ClockInterface::class], $config->clock);
        self::assertSame($ports[EventDispatcherInterface::class], $config->dispatcher);
        self::assertSame($ports[LoggerInterface::class], $config->logger);
        self::assertSame($ports[RateLimitConfig::class], $config->rateLimits);
        self::assertSame($ports[ResponseFactoryInterface::class], $config->responseFactory);
    }

    public function testSecretsAndAuthSettingsComeFromTheEnvironmentWhenNotBound(): void
    {
        $keys = TestKeys::rsa();
        putenv('APP_KEY=' . TestPolaris::APP_KEY);
        putenv('AUTH_JWT_PRIVATE_KEY=' . $keys['private']);
        putenv('AUTH_JWT_PUBLIC_KEY=' . $keys['public']);
        putenv('AUTH_ISSUER=https://issuer.example.com');
        putenv('AUTH_AUDIENCE=https://api.example.com');
        putenv('AUTH_ACCESS_TOKEN_DENYLIST=1');
        putenv('AUTH_PASSWORD_BREACH_CHECK=on');
        $container = new Container();
        $container->instance(DatabaseAdapter::class, new InMemoryAdapter());

        $config = PolarisConfig::fromContainer($container, new Env());

        self::assertSame(trim($keys['public']), trim($config->secrets->jwtPublicKey));
        self::assertSame('https://issuer.example.com', $config->auth->issuer);
        self::assertSame('https://api.example.com', $config->auth->audience);
        self::assertTrue($config->auth->accessToken->denylist);
        self::assertTrue($config->auth->breachCheck);
        self::assertNull($config->mailer);
        self::assertNull($config->cache);
        self::assertNull($config->logger);
    }

    public function testAHostBoundPdoIsWrappedInThePdoAdapter(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $container = $this->container([PDO::class => $pdo]);

        $database = PolarisConfig::fromContainer($container, new Env())->database;

        self::assertInstanceOf(PdoAdapter::class, $database);
        self::assertSame($pdo, $database->pdo());
    }

    public function testTheFrameworkDatabaseSettingsOpenAConnectionBesideCycles(): void
    {
        $container = $this->container([DatabaseSettings::class => new DatabaseSettings(DatabaseSettings::DRIVER_SQLITE, ':memory:')]);

        $database = PolarisConfig::fromContainer($container, new Env())->database;

        self::assertInstanceOf(PdoAdapter::class, $database);
        self::assertSame(Dialect::Sqlite, $database->dialect());
    }

    public function testTheEnvironmentOpensAConnectionWhenNothingIsBound(): void
    {
        putenv('POLARIS_DSN=sqlite::memory:');

        $database = PolarisConfig::fromContainer($this->container(), new Env())->database;

        self::assertInstanceOf(PdoAdapter::class, $database);
        self::assertSame(Dialect::Sqlite, $database->dialect());
    }

    public function testWithoutAnyDatabaseTheErrorSaysWhatToConfigure(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('POLARIS_DSN');
        PolarisConfig::fromContainer($this->container(), new Env());
    }

    public function testWithoutADispatcherPolarisEventsReachThePolarisListeners(): void
    {
        $adapter = new InMemoryAdapter();
        $graph = TestPolaris::graph(TestPolaris::boot([DatabaseAdapter::class => $adapter]));
        self::assertInstanceOf(ListenerDispatcher::class, $graph->events());

        $graph->events()->dispatch(new UserRegistered('user-1', 'ada@example.com', 'verification-token'));

        $rows = $adapter->findMany('auth_audit_log', []);
        self::assertCount(1, $rows);
        self::assertSame('user.registered', $rows[0]['event']);
    }

    public function testThePathPrefixComesFromTheEnvironment(): void
    {
        self::assertSame('/', PolarisConfig::pathPrefix(new Env()));
        putenv('POLARIS_PATH_PREFIX=/api');
        self::assertSame('/api', PolarisConfig::pathPrefix(new Env()));
    }

    /**
     * @param array<class-string, object> $instances
     */
    private function container(array $instances = []): Container
    {
        $container = new Container();
        $container->instance(Secrets::class, TestPolaris::secrets());
        $container->instance(AuthConfig::class, TestPolaris::auth());
        foreach ($instances as $id => $instance) {
            $container->instance($id, $instance);
        }

        return $container;
    }
}
