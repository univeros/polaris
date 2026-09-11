<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database;

use Altair\Configuration\Support\Env;
use Altair\Persistence\Configuration\DatabaseSettings;
use Altair\Persistence\Exception\InvalidConfigurationException;
use PDO;
use Polaris\Cli\Database;

use function is_string;
use function sprintf;

/**
 * The PDO connection Polaris uses beside Cycle's, on the same settings: Cycle's
 * `Driver::getPDO()` is protected, so the handle cannot be shared. `DB_CONNECTION` and the other
 * `DB_*` variables `CycleOrmConfiguration` reads come first; `POLARIS_DSN` (with
 * `POLARIS_DB_USER` and `POLARIS_DB_PASSWORD`) serves an application without an ORM.
 */
final class Connection
{
    private const array DB_KEYS = ['DB_CONNECTION', 'DB_DATABASE', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_CHARSET'];

    public static function fromEnvironment(?Env $env = null): PDO
    {
        $env ??= new Env();
        $environment = self::databaseEnvironment($env);
        if (($environment['DB_CONNECTION'] ?? '') !== '') {
            return self::fromSettings(DatabaseSettings::fromEnv($environment));
        }
        $dsn = $env->get('POLARIS_DSN');
        if (is_string($dsn) && $dsn !== '') {
            return self::fromDsn($dsn, self::string($env->get('POLARIS_DB_USER')), self::string($env->get('POLARIS_DB_PASSWORD')));
        }

        throw new InvalidConfigurationException(
            'Polaris needs a database: bind a Polaris\Contract\DatabaseAdapter or a PDO, configure DB_CONNECTION and'
            . ' DB_DATABASE (what CycleOrmConfiguration reads), or set POLARIS_DSN.',
        );
    }

    public static function fromSettings(DatabaseSettings $settings): PDO
    {
        return match ($settings->driver) {
            DatabaseSettings::DRIVER_SQLITE => self::fromDsn('sqlite:' . $settings->database, null, null),
            DatabaseSettings::DRIVER_POSTGRES => self::fromDsn(
                sprintf('pgsql:host=%s;port=%d;dbname=%s', $settings->tcpHost(), $settings->tcpPort(), $settings->database),
                $settings->tcpUser(),
                $settings->tcpPassword(),
            ),
            DatabaseSettings::DRIVER_MYSQL => self::fromDsn(
                sprintf(
                    'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                    $settings->tcpHost(),
                    $settings->tcpPort(),
                    $settings->database,
                    $settings->tcpCharset() ?? 'utf8',
                ),
                $settings->tcpUser(),
                $settings->tcpPassword(),
            ),
            default => throw new InvalidConfigurationException(sprintf(
                'Polaris runs on the postgres, mysql and sqlite drivers; DB_CONNECTION is "%s".',
                $settings->driver,
            )),
        };
    }

    /**
     * A PDO in exception mode, with `PRAGMA foreign_keys = ON` on SQLite.
     */
    public static function fromDsn(string $dsn, ?string $user, ?string $password): PDO
    {
        return Database::connect($dsn, $user, $password);
    }

    /**
     * The `DB_*` variables as {@see DatabaseSettings::fromEnv()} takes them.
     *
     * @return array<string, string|null>
     */
    public static function databaseEnvironment(Env $env): array
    {
        $values = [];
        foreach (self::DB_KEYS as $key) {
            $values[$key] = self::string($env->get($key));
        }

        return $values;
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
