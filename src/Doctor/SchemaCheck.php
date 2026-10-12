<?php

declare(strict_types=1);

namespace Univeros\Polaris\Doctor;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Doctor\Contracts\CheckInterface;
use Altair\Doctor\Result\CheckResult;
use Override;
use Polaris\Cli\Database;
use Polaris\Pdo\SchemaDiff;
use Polaris\Pdo\SchemaInspector;
use Polaris\Schema\Schema;
use Throwable;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Database\Connection;

use function array_slice;
use function count;
use function implode;
use function sprintf;

/**
 * `polaris_schema` in `bin/altair doctor`: the database matches the Polaris schema, the configured
 * plugins' tables included (`polaris:schema:diff`).
 */
final readonly class SchemaCheck implements CheckInterface
{
    public function __construct(private Container $container, private Env $env)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'polaris_schema';
    }

    #[Override]
    public function dependsOn(): array
    {
        return [];
    }

    #[Override]
    public function run(): CheckResult
    {
        try {
            foreach (PolarisConfig::plugins($this->container, $this->env) as $plugin) {
                Schema::register(...$plugin->schema());
            }
            $pdo = Connection::fromContainer($this->container, $this->env);
            $dialect = Database::dialectOf($pdo);
            $differences = (new SchemaDiff(new SchemaInspector($pdo, $dialect), $dialect))->run();
        } catch (Throwable $exception) {
            return CheckResult::error($this->name(), $exception->getMessage(), 'Check the database settings (DB_* or POLARIS_DSN) and the plugins.');
        }
        if ($differences === []) {
            return CheckResult::ok($this->name(), 'The database matches the Polaris schema.');
        }

        return CheckResult::error(
            $this->name(),
            sprintf('%d difference(s): %s', count($differences), implode('; ', array_slice($differences, 0, 5))),
            'Run bin/altair db:migrate on a fresh database, then bin/altair polaris:schema:install-plugins for the plugins\' tables.',
        );
    }
}
