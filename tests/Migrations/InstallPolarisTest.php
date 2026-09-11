<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Migrations;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Module\ModuleConfiguration;
use Altair\Persistence\Configuration\DatabaseConnectionFactory;
use Altair\Persistence\Configuration\DatabaseSettings;
use Altair\Persistence\Migrations\MigrationConfigFactory;
use Altair\Persistence\Migrations\MigratorFactory;
use Altair\Persistence\Migrations\ModuleMigrationDirectories;
use Cycle\Migrations\Migrator;
use Cycle\Migrations\State;
use PHPUnit\Framework\TestCase;
use Polaris\Cli\Database;
use Polaris\Pdo\SchemaDiff;
use Polaris\Pdo\SchemaInspector;
use Univeros\Polaris\Database\Connection;
use Univeros\Polaris\Module;

use function getenv;
use function getmypid;
use function is_file;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * The one migration through Cycle's {@see Migrator} as `bin/altair db:migrate` runs it: the module's
 * directory discovered through the container tag, applied once, `polaris:schema:diff` clean, rolled
 * back. On the `DB_*` database when the environment sets one (PostgreSQL in CI), else a SQLite file.
 */
final class InstallPolarisTest extends TestCase
{
    private ?string $file = null;
    private string $hostMigrations;
    private DatabaseSettings $settings;
    private Migrator $migrator;

    protected function setUp(): void
    {
        if ((string) getenv('DB_CONNECTION') === '') {
            $this->file = (string) tempnam(sys_get_temp_dir(), 'polaris-migration-');
            $this->settings = new DatabaseSettings(DatabaseSettings::DRIVER_SQLITE, $this->file);
        } else {
            $this->settings = DatabaseSettings::fromEnv(Connection::databaseEnvironment(new Env()));
        }
        $this->hostMigrations = sys_get_temp_dir() . '/polaris-host-migrations-' . getmypid();
        @mkdir($this->hostMigrations);

        $container = new Container();
        (new ModuleConfiguration([new Module()]))->apply($container);
        $config = (new MigrationConfigFactory())->create(
            $this->hostMigrations,
            vendorDirectories: ModuleMigrationDirectories::existingFor($container),
        );
        $this->migrator = (new MigratorFactory())->create((new DatabaseConnectionFactory())->create($this->settings), $config);
    }

    protected function tearDown(): void
    {
        while ($this->migrator->rollback() !== null) {
        }
        if ($this->file !== null && is_file($this->file)) {
            unlink($this->file);
        }
        @rmdir($this->hostMigrations);
    }

    public function testDbMigrateInstallsPolarisOnceAndRollbackDropsIt(): void
    {
        $pending = $this->migrator->getMigrations();
        self::assertCount(1, $pending);
        self::assertSame('install_polaris', $pending[0]->getState()->getName());
        self::assertSame(State::STATUS_PENDING, $pending[0]->getState()->getStatus());

        $applied = $this->migrator->run();
        self::assertNotNull($applied);
        self::assertSame(State::STATUS_EXECUTED, $applied->getState()->getStatus());
        self::assertSame([], $this->differences(), 'polaris:schema:diff is clean after db:migrate');

        self::assertNull($this->migrator->run(), 'applied once: a second db:migrate has nothing to do');

        $rolledBack = $this->migrator->rollback();
        self::assertNotNull($rolledBack);
        self::assertSame(State::STATUS_PENDING, $rolledBack->getState()->getStatus());
        self::assertNotSame([], $this->differences(), 'the tables are gone');
    }

    /**
     * What `polaris:schema:diff` reports on the same settings.
     *
     * @return list<string>
     */
    private function differences(): array
    {
        $pdo = Connection::fromSettings($this->settings);
        $dialect = Database::dialectOf($pdo);

        return (new SchemaDiff(new SchemaInspector($pdo, $dialect), $dialect))->run();
    }
}
