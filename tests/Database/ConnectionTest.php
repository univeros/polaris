<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Database;

use Altair\Persistence\Configuration\DatabaseSettings;
use Altair\Persistence\Exception\InvalidConfigurationException;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Database\Connection;
use Univeros\Polaris\Tests\Support\ArrayEnv;

final class ConnectionTest extends TestCase
{
    public function testSqliteSettingsOpenAConnectionWithForeignKeysOn(): void
    {
        $pdo = Connection::fromSettings(new DatabaseSettings(DatabaseSettings::DRIVER_SQLITE, ':memory:'));

        self::assertSame('sqlite', $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME));
        self::assertSame(1, (int) $pdo->query('PRAGMA foreign_keys')->fetchColumn());
        self::assertSame(\PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(\PDO::ATTR_ERRMODE));
    }

    public function testTheDbVariablesCycleReadsComeFirst(): void
    {
        $env = new ArrayEnv(['DB_CONNECTION' => 'sqlite', 'DB_DATABASE' => ':memory:', 'POLARIS_DSN' => 'bogus:never-used']);

        self::assertSame('sqlite', Connection::fromEnvironment($env)->getAttribute(\PDO::ATTR_DRIVER_NAME));
    }

    public function testPolarisDsnServesAnApplicationWithoutAnOrm(): void
    {
        $env = new ArrayEnv(['POLARIS_DSN' => 'sqlite::memory:']);

        self::assertSame('sqlite', Connection::fromEnvironment($env)->getAttribute(\PDO::ATTR_DRIVER_NAME));
    }

    public function testTheDbVariablesAreReadAsDatabaseSettingsTakeThem(): void
    {
        $env = new ArrayEnv(['DB_CONNECTION' => 'postgres', 'DB_DATABASE' => 'polaris', 'DB_HOST' => 'db.internal', 'DB_PORT' => '']);

        $environment = Connection::databaseEnvironment($env);

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
        Connection::fromEnvironment(new ArrayEnv([]));
    }
}
