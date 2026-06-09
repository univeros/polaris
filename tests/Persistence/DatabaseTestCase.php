<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Configuration\DatabaseConnectionFactory;
use Altair\Persistence\Configuration\DatabaseSettings;
use Altair\Persistence\Cycle\CycleUnitOfWork;
use Altair\Persistence\Migrations\MigrationConfigFactory;
use Altair\Persistence\Migrations\MigratorFactory;
use Altair\Persistence\Schema\AttributeSchemaProvider;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\DatabaseProviderInterface;
use Cycle\Migrations\Migrator;
use Cycle\ORM\Factory;
use Cycle\ORM\ORM;
use Cycle\ORM\ORMInterface;
use Cycle\ORM\Schema;
use PHPUnit\Framework\TestCase;
use Throwable;

use function dirname;
use function getenv;

/**
 * Base class for Polaris persistence tests.
 *
 * These tests run against a **real database driver** — never SQLite — chosen from
 * the environment (`DB_CONNECTION`, `DB_DATABASE`, …) and built with the same
 * {@see DatabaseConnectionFactory} the framework uses at runtime. CI runs them
 * against PostgreSQL; a developer can point them at MySQL/SQL Server/etc. by
 * exporting the same env vars. When no database is configured the whole suite is
 * skipped rather than silently falling back to an in-memory engine, so the
 * entities and migrations are always exercised against a production-grade driver.
 *
 * Each test runs the module's real migrations to build the schema, then drives a
 * Cycle ORM wired from the entity attributes — proving the migrations and the
 * entities agree on a portable schema.
 */
abstract class DatabaseTestCase extends TestCase
{
    private const array ENV_KEYS = [
        'DB_CONNECTION',
        'DB_DATABASE',
        'DB_HOST',
        'DB_PORT',
        'DB_USER',
        'DB_PASSWORD',
        'DB_CHARSET',
    ];

    protected ?DatabaseProviderInterface $database = null;
    protected ORMInterface $orm;
    protected CycleUnitOfWork $unitOfWork;
    protected Migrator $migrator;

    protected function setUp(): void
    {
        $env = $this->testEnvironment();

        if (($env['DB_CONNECTION'] ?? '') === '') {
            self::markTestSkipped(
                'Database integration tests require a real driver. Export DB_CONNECTION and '
                . 'DB_DATABASE (plus DB_HOST/DB_PORT/DB_USER/DB_PASSWORD for server drivers) to '
                . 'run them — for example against PostgreSQL or MySQL. SQLite is intentionally not used.',
            );
        }

        $this->database = (new DatabaseConnectionFactory())->create(DatabaseSettings::fromEnv($env));
        $this->dropAllTables();

        $config = (new MigrationConfigFactory())->create(
            directory: self::path('database/migrations'),
            namespace: 'Univeros\\Polaris\\Database\\Migrations',
            safe: true,
        );
        $this->migrator = (new MigratorFactory())->create($this->database, $config);
        while ($this->migrator->run() !== null) {
            // Apply every pending migration.
        }

        $schema = (new AttributeSchemaProvider($this->database, [self::path('src/Entity')]))->schema();
        $this->orm = new ORM(new Factory($this->database), new Schema($schema));
        $this->unitOfWork = new CycleUnitOfWork($this->orm);
    }

    protected function tearDown(): void
    {
        if ($this->database !== null) {
            $this->dropAllTables();
        }
    }

    /**
     * The default-connection database, asserted to be booted.
     */
    protected function connection(): DatabaseInterface
    {
        $database = $this->database;
        if ($database === null) {
            self::fail('Database connection was not booted.');
        }

        return $database->database('default');
    }

    /**
     * Drops every table so each test starts from a clean, dedicated database.
     *
     * The RBAC join tables (`auth_role_permissions`, `auth_membership_roles`) carry cascading
     * foreign keys, so a parent cannot be dropped while a child still references it. Rather than
     * reflect each table's foreign keys — an `information_schema` query that is slow under load and
     * would run for every table on every test — we simply drop what we can and retry the rest: a
     * still-referenced table fails and succeeds on a later pass once its children are gone.
     * Portable: plain `DROP TABLE`, no driver-specific SQL, no schema introspection.
     */
    private function dropAllTables(): void
    {
        $database = $this->database;
        if ($database === null) {
            return;
        }

        $connection = $database->database('default');

        $remaining = [];
        foreach ($connection->getTables() as $table) {
            $remaining[] = $table->getName();
        }

        while ($remaining !== []) {
            $progressed = false;
            foreach ($remaining as $index => $name) {
                try {
                    $connection->execute('DROP TABLE IF EXISTS ' . $name);
                } catch (Throwable) {
                    continue; // still referenced by another remaining table; retry next pass
                }
                unset($remaining[$index]);
                $progressed = true;
            }

            if (!$progressed) {
                break;
            }
        }
    }

    /**
     * @return array<string, string>
     */
    private function testEnvironment(): array
    {
        $env = [];
        foreach (self::ENV_KEYS as $key) {
            $value = getenv($key);
            if ($value !== false) {
                $env[$key] = $value;
            }
        }

        return $env;
    }

    private static function path(string $relative): string
    {
        return dirname(__DIR__, 2) . '/' . $relative;
    }
}
