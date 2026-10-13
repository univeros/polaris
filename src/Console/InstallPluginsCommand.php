<?php

declare(strict_types=1);

namespace Univeros\Polaris\Console;

use Closure;
use PDO;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\Plugin;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SchemaInstaller;
use Polaris\Pdo\SchemaInspector;
use Polaris\Pdo\SqlSchema;
use Polaris\Schema\Schema;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function count;
use function implode;
use function sprintf;

/**
 * `polaris:schema:install-plugins`: creates the tables the database lacks (a plugin enabled after
 * `db:migrate` installed core) and seeds the permission catalog with the plugins' permissions. Safe
 * to re-run: existing tables are left alone and the seeder only adds what is missing. `--sql` prints
 * the statements instead, for a host that keeps its schema in its own migrations.
 */
final class InstallPluginsCommand extends Command
{
    /**
     * @param Closure(): PDO $connection
     * @param Closure(): list<Plugin> $plugins
     */
    public function __construct(private readonly Closure $connection, private readonly Closure $plugins)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('polaris:schema:install-plugins')
            ->setDescription('Creates the missing Polaris tables (the plugins\' included) and seeds their permissions.')
            ->addOption('sql', null, InputOption::VALUE_NONE, 'Print the statements instead of running them');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $plugins = ($this->plugins)();
            foreach ($plugins as $plugin) {
                Schema::register(...$plugin->schema());
            }
            $pdo = ($this->connection)();
            if ($input->getOption('sql') === true) {
                foreach (self::statements(new PdoAdapter($pdo)) as $statement) {
                    $output->writeln($statement . ';');
                }

                return Command::SUCCESS;
            }
            $created = SchemaInstaller::createMissing($pdo, catalog: new PermissionCatalog($plugins));
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln($created === []
            ? '<info>No table to create. Seeded the permission catalog.</info>'
            : sprintf('<info>Created %d table(s): %s. Seeded the permission catalog.</info>', count($created), implode(', ', $created)));

        return Command::SUCCESS;
    }

    /**
     * The statements `createMissing()` would run, for `--sql`.
     *
     * @return list<string>
     */
    private static function statements(PdoAdapter $adapter): array
    {
        $inspector = new SchemaInspector($adapter->pdo(), $adapter->dialect());
        $statements = [];
        foreach (SqlSchema::ordered() as $model) {
            if ($inspector->table($model->table) === null) {
                $statements = [...$statements, ...SqlSchema::create($model, $adapter->dialect())];
            }
        }

        return $statements;
    }
}
