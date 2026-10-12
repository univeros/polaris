<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Doctor;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Doctor\CheckRegistry;
use Altair\Doctor\Contracts\CheckInterface;
use Altair\Doctor\Result\CheckResult;
use Altair\Doctor\Result\CheckStatus;
use PDO;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Passwordless\PasswordlessPlugin;
use Polaris\Pdo\SchemaInstaller;
use Polaris\Username\UsernamePlugin;
use Univeros\Polaris\Module;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\ArrayEnv;
use Univeros\Polaris\Tests\Support\TestPolaris;

use function array_map;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

final class DoctorChecksTest extends TestCase
{
    private string $file;
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->file = (string) tempnam(sys_get_temp_dir(), 'polaris-doctor-');
        $this->pdo = new PDO('sqlite:' . $this->file);
    }

    protected function tearDown(): void
    {
        unlink($this->file);
    }

    public function testThePolarisChecksJoinTheDoctorWhenItIsInstalled(): void
    {
        $registry = $this->registry([]);

        self::assertSame(
            ['polaris', 'polaris_plugins', 'polaris_schema'],
            array_map(static fn(CheckInterface $check): string => $check->name(), $registry->all()),
        );
    }

    public function testWithoutTheDoctorTheModuleAppliesAsBefore(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        self::assertFalse($container->has(CheckRegistry::class));
    }

    public function testPolarisIsReadyWithItsSecretsAndDatabase(): void
    {
        SchemaInstaller::create($this->pdo);

        self::assertSame(CheckStatus::Ok, $this->check('polaris', [])->status);
    }

    public function testMissingSecretsAreAnErrorWithAFix(): void
    {
        $result = $this->check('polaris', [], secrets: false);

        self::assertSame(CheckStatus::Error, $result->status);
        self::assertNotNull($result->fix);
    }

    public function testThePluginsCheckNamesTheConfiguredPlugins(): void
    {
        $result = $this->check('polaris_plugins', [Plugins::class => new Plugins(new UsernamePlugin())]);

        self::assertSame(CheckStatus::Ok, $result->status);
        self::assertStringContainsString('username', $result->detail);
    }

    public function testABaseUrlOffThePathPrefixIsAnError(): void
    {
        $plugins = new Plugins(new PasswordlessPlugin(baseUrl: 'https://app.example.com/auth'));

        $off = $this->check('polaris_plugins', [Plugins::class => $plugins]);
        $on = $this->check('polaris_plugins', [Plugins::class => $plugins], ['POLARIS_PATH_PREFIX' => '/auth']);

        self::assertSame(CheckStatus::Error, $off->status);
        self::assertStringContainsString('passwordless', $off->detail);
        self::assertSame(CheckStatus::Ok, $on->status, $on->detail);
    }

    public function testABadPluginEntryIsAnError(): void
    {
        $result = $this->check('polaris_plugins', [], ['POLARIS_PLUGINS' => 'App\\Missing']);

        self::assertSame(CheckStatus::Error, $result->status);
        self::assertStringContainsString('App\\Missing', $result->detail);
    }

    public function testAMissingPluginTableIsAnErrorFixedByInstallPlugins(): void
    {
        SchemaInstaller::create($this->pdo);
        // Schema::all() is process-wide: another test may have registered username's model already.
        $this->pdo->exec('DROP TABLE IF EXISTS "polaris_username"');

        $missing = $this->check('polaris_schema', [Plugins::class => new Plugins(new UsernamePlugin())]);

        self::assertSame(CheckStatus::Error, $missing->status);
        self::assertStringContainsString('polaris:schema:install-plugins', (string) $missing->fix);
    }

    /**
     * @param array<class-string, object> $instances
     * @param array<string, string> $env
     */
    private function check(string $name, array $instances, array $env = [], bool $secrets = true): CheckResult
    {
        foreach ($this->registry($instances, $env, $secrets)->all() as $check) {
            if ($check->name() === $name) {
                return $check->run();
            }
        }
        self::fail('No check ' . $name);
    }

    /**
     * @param array<class-string, object> $instances
     * @param array<string, string> $env
     */
    private function registry(array $instances, array $env = [], bool $secrets = true): CheckRegistry
    {
        $container = new Container();
        // As DoctorConfiguration binds it (a shared factory), before the modules apply.
        $container->factory(CheckRegistry::class, static fn(): CheckRegistry => new CheckRegistry())->shared();
        $container->instance(PDO::class, $this->pdo);
        $container->instance(Env::class, new ArrayEnv($env));
        if ($secrets) {
            $container->instance(Secrets::class, TestPolaris::secrets());
            $container->instance(AuthConfig::class, TestPolaris::auth());
        }
        foreach ($instances as $id => $instance) {
            $container->instance($id, $instance);
        }
        (new Module())->apply($container);
        $registry = $container->get(CheckRegistry::class);
        \assert($registry instanceof CheckRegistry);

        return $registry;
    }
}
