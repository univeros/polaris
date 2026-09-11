<?php

declare(strict_types=1);

namespace Univeros\Polaris\Migrations;

use Cycle\Database\Driver\Driver;
use Cycle\Migrations\Exception\MigrationException;
use Cycle\Migrations\Migration;
use PDO;
use Polaris\Pdo\SchemaInstaller;
use ReflectionMethod;

use function sprintf;

/**
 * Installs Polaris: the tables for the connection's dialect, then the permission catalog and the
 * system roles ({@see SchemaInstaller}), on Cycle's own connection inside the transaction Cycle
 * wraps around `up()`. One connection is what makes this work: with the framework's statement
 * cache, Cycle's migrator leaves a cursor open on SQLite that blocks any other connection's
 * commit, and on PostgreSQL the install is atomic with the migration record.
 * `bin/altair polaris:schema:diff` proves the result.
 */
final class InstallPolaris extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        SchemaInstaller::create($this->pdo());
    }

    public function down(): void
    {
        SchemaInstaller::drop($this->pdo());
    }

    /**
     * Cycle keeps `Driver::getPDO()` protected; the handle is the one the migrator's transaction
     * runs on, which is exactly the point. The migrator's own state queries leave cached cursors
     * open on this connection, and on SQLite a pending cursor makes `DROP TABLE` fail with
     * "database table is locked": clearing the statement cache finalises them.
     */
    private function pdo(): PDO
    {
        $driver = $this->database()->getDriver();
        if (!$driver instanceof Driver) {
            throw new MigrationException(sprintf('Polaris installs through a Cycle PDO driver, not %s.', $driver::class));
        }
        $driver->clearCache();
        $pdo = (new ReflectionMethod($driver, 'getPDO'))->invoke($driver);
        if (!$pdo instanceof PDO) {
            throw new MigrationException('Polaris installs through PDO; the Cycle driver runs on something else.');
        }

        return $pdo;
    }
}
