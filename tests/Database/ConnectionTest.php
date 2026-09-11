<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Database;

use Altair\Configuration\Support\Env;
use Altair\Persistence\Configuration\DatabaseSettings;
use Altair\Persistence\Exception\InvalidConfigurationException;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Database\Connection;

use function putenv;

final class ConnectionTest extends TestCase
{
    protected function tearDown(): void
    {
        foreach (['POLARIS_DSN', 'POLARIS_DB_USER', 'POLARIS_DB_PASSWORD', 'DB_CONNECTION', 'DB_DATABASE', 'DB_HOST', 'DB_PORT'] as $key) {
            putenv($key);
        }
    }

    public function testSqliteSettingsOpenAConnectionWithForeignKeysOn(): void
    {
        $pdo = Connection::fromSettings(new DatabaseSettings(DatabaseSettings::DRIVER_SQLITE, ':memory:'));

        self::assertSame('sqlite', $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME));
        self::assertSame(1, (int) $pdo->query('PRAGMA foreign_keys')->fetchColumn());
        self::assertSame(\PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(\PDO::ATTR_ERRMODE));
    }

    public function testTheDbVariablesCycleReadsComeFirst(): void
    {
        putenv('DB_CONNECTION=sqlite');
        putenv('DB_DATABASE=:memory:');
        putenv('POLARIS_DSN=bogus:never-used');

        self::assertSame('sqlite', Connection::fromEnvironment(new Env())->getAttribute(\PDO::ATTR_DRIVER_NAME));
    }

    public function testPolarisDsnServesAnApplicationWithoutAnOrm(): void
    {
        putenv('POLARIS_DSN=sqlite::memory:');

        self::assertSame('sqlite', Connection::fromEnvironment(new Env())->getAttribute(\PDO::ATTR_DRIVER_NAME));
    }

    public function testTheDbVariablesAreReadAsDatabaseSettingsTakeThem(): void
    {
        putenv('DB_CONNECTION=postgres');
        putenv('DB_DATABASE=polaris');
        putenv('DB_HOST=db.internal');

        $environment = Connection::databaseEnvironment(new Env());

        self::assertSame('postgres', $environment['DB_CONNECTION']);
        self::assertSame('polaris', $environment['DB_DATABASE']);
        self::assertSame('db.internal', $environment['DB_HOST']);
        self::assertNull($environment['DB_PORT']);
        self::assertSame(5432, DatabaseSettings::fromEnv($environment)->port);
    }

    public function testAnUnsupportedDriverIsRefusedWithTheSupportedOnes(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('postgres, mysql and sqlite');
        Connection::fromSettings(new DatabaseSettings(DatabaseSettings::DRIVER_SQLSERVER, 'polaris', 'db', 1433));
    }

    public function testNoDatabaseAtAllIsRefusedWithWhatToConfigure(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('DB_CONNECTION');
        Connection::fromEnvironment(new Env());
    }
}
