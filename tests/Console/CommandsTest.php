<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Console;

use Altair\Cli\Application;
use Altair\Container\Container;
use PDO;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Username\UsernamePlugin;
use Symfony\Component\Console\Tester\CommandTester;
use Univeros\Polaris\Console\Commands;
use Univeros\Polaris\Module;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\HeaderPlugin;
use Univeros\Polaris\Tests\Support\TestPolaris;

use function array_map;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

final class CommandsTest extends TestCase
{
    private const array NAMES = [
        'polaris:schema:export',
        'polaris:schema:create',
        'polaris:schema:drop',
        'polaris:schema:diff',
        'polaris:manifest',
        'polaris:doctor',
        'polaris:schema:install-plugins',
    ];

    public function testThePolarisCommandsAreListedByTheFrameworkApplication(): void
    {
        $container = TestPolaris::boot();
        $application = new Application($container);

        foreach (Commands::all($container) as $command) {
            $application->add($command);
        }

        foreach (self::NAMES as $name) {
            self::assertTrue($application->has($name), $name);
        }
        self::assertSame(self::NAMES, array_map(static fn($c): string => (string) $c->getName(), Commands::all($container)));
    }

    public function testTheSchemaCommandsAndTheDoctorRunOnTheModulesConnection(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-commands-');
        $pdo = new PDO('sqlite:' . $file);
        $container = new Container();
        $container->instance(PDO::class, $pdo);
        $container->instance(Secrets::class, TestPolaris::secrets());
        $container->instance(AuthConfig::class, TestPolaris::auth());
        (new Module())->apply($container);
        $application = new Application($container);
        foreach (Commands::all($container) as $command) {
            $application->add($command);
        }

        try {
            $create = new CommandTester($application->find('polaris:schema:create'));
            self::assertSame(0, $create->execute([]), $create->getDisplay());

            $diff = new CommandTester($application->find('polaris:schema:diff'));
            self::assertSame(0, $diff->execute([]), $diff->getDisplay());
            self::assertStringContainsString('matches the Polaris schema', $diff->getDisplay());

            $doctor = new CommandTester($application->find('polaris:doctor'));
            self::assertSame(0, $doctor->execute([]), $doctor->getDisplay());
            self::assertStringContainsString('Polaris is ready.', $doctor->getDisplay());

            $drop = new CommandTester($application->find('polaris:schema:drop'));
            self::assertSame(0, $drop->execute([]), $drop->getDisplay());
            self::assertSame(1, $diff->execute([]), 'the tables are gone');
        } finally {
            unlink($file);
        }
    }

    public function testManifestAndExportNeedNoDatabase(): void
    {
        $container = new Container();
        (new Module())->apply($container);
        $application = new Application($container);
        foreach (Commands::all($container) as $command) {
            $application->add($command);
        }

        $manifest = new CommandTester($application->find('polaris:manifest'));
        self::assertSame(0, $manifest->execute([]));
        self::assertStringContainsString('/auth/login', $manifest->getDisplay());

        $export = new CommandTester($application->find('polaris:schema:export'));
        self::assertSame(0, $export->execute(['--target' => 'sql:sqlite']));
        self::assertStringContainsString('CREATE TABLE "auth_users"', $export->getDisplay());
    }

    public function testInstallPluginsCreatesTheMissingPluginTablesAndSeedsTheirPermissions(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-plugins-');
        $pdo = new PDO('sqlite:' . $file);
        $application = self::application($pdo, new Plugins(new UsernamePlugin(), new HeaderPlugin()));

        try {
            $create = new CommandTester($application->find('polaris:schema:create'));
            self::assertSame(0, $create->execute([]), $create->getDisplay());
            $pdo->exec('DROP TABLE "polaris_username"');

            $install = new CommandTester($application->find('polaris:schema:install-plugins'));
            self::assertSame(0, $install->execute([]), $install->getDisplay());
            self::assertStringContainsString('polaris_username', $install->getDisplay());

            $diff = new CommandTester($application->find('polaris:schema:diff'));
            self::assertSame(0, $diff->execute([]), $diff->getDisplay());
            $permission = $pdo->query("SELECT COUNT(*) FROM auth_permissions WHERE key = 'header.read'");
            self::assertNotFalse($permission);
            self::assertSame(1, (int) $permission->fetchColumn());

            self::assertSame(0, $install->execute([]), 'a second run has nothing to create');
            self::assertStringContainsString('No table to create', $install->getDisplay());
        } finally {
            unlink($file);
        }
    }

    public function testInstallPluginsSqlPrintsTheStatementsWithoutRunningThem(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-plugins-');
        $pdo = new PDO('sqlite:' . $file);
        $application = self::application($pdo, new Plugins(new UsernamePlugin()));

        try {
            (new CommandTester($application->find('polaris:schema:create')))->execute([]);
            $pdo->exec('DROP TABLE "polaris_username"');

            $install = new CommandTester($application->find('polaris:schema:install-plugins'));
            self::assertSame(0, $install->execute(['--sql' => true]), $install->getDisplay());
            self::assertStringContainsString('CREATE TABLE "polaris_username"', $install->getDisplay());
            self::assertStringNotContainsString('CREATE TABLE "auth_users"', $install->getDisplay());

            $diff = new CommandTester($application->find('polaris:schema:diff'));
            self::assertSame(1, $diff->execute([]), 'nothing was created');
        } finally {
            unlink($file);
        }
    }

    public function testAConfiguredPluginsCommandsJoinAsPolarisCommands(): void
    {
        $application = self::application(new PDO('sqlite::memory:'), new Plugins(new HeaderPlugin()));

        $ping = new CommandTester($application->find('polaris:header:ping'));

        self::assertSame(0, $ping->execute([]));
        self::assertStringContainsString('pong from header', $ping->getDisplay());
    }

    public function testManifestAndExportIncludeTheConfiguredPlugins(): void
    {
        $application = self::application(new PDO('sqlite::memory:'), new Plugins(new UsernamePlugin()));

        $manifest = new CommandTester($application->find('polaris:manifest'));
        self::assertSame(0, $manifest->execute([]), $manifest->getDisplay());
        self::assertStringContainsString('/username/sign-in', $manifest->getDisplay());

        $export = new CommandTester($application->find('polaris:schema:export'));
        self::assertSame(0, $export->execute(['--target' => 'sql:sqlite']), $export->getDisplay());
        self::assertStringContainsString('CREATE TABLE "polaris_username"', $export->getDisplay());
    }

    private static function application(PDO $pdo, Plugins $plugins): Application
    {
        $container = new Container();
        $container->instance(PDO::class, $pdo);
        $container->instance(Plugins::class, $plugins);
        $container->instance(Secrets::class, TestPolaris::secrets());
        $container->instance(AuthConfig::class, TestPolaris::auth());
        (new Module())->apply($container);
        $application = new Application($container);
        foreach (Commands::all($container) as $command) {
            $application->add($command);
        }

        return $application;
    }
}
