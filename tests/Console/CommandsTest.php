<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Console;

use Altair\Cli\Application;
use Altair\Container\Container;
use PDO;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Symfony\Component\Console\Tester\CommandTester;
use Univeros\Polaris\Console\Commands;
use Univeros\Polaris\Module;
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
    ];

    public function testTheSixPolarisCommandsAreListedByTheFrameworkApplication(): void
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
}
