<?php

declare(strict_types=1);

namespace Univeros\Polaris\Console;

use Closure;
use DateTimeImmutable;
use PDO;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;
use Polaris\Cli\Database;
use Polaris\Contract\Plugin;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SchemaInspector;
use Polaris\Pdo\SqlSchema;
use Polaris\Schema\Model;
use Polaris\Schema\Schema;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function array_column;
use function array_filter;
use function array_values;
use function count;
use function implode;
use function in_array;
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
            $dialect = Database::dialectOf($pdo);
            $inspector = new SchemaInspector($pdo, $dialect);
            $missing = self::ordered(array_values(array_filter(Schema::all(), static fn(Model $model): bool => $inspector->table($model->table) === null)));
            $statements = [];
            foreach ($missing as $model) {
                $statements = [...$statements, ...SqlSchema::create($model, $dialect)];
            }
            if ($input->getOption('sql') === true) {
                foreach ($statements as $statement) {
                    $output->writeln($statement . ';');
                }

                return Command::SUCCESS;
            }
            foreach ($statements as $statement) {
                $pdo->exec($statement);
            }
            (new PermissionCatalogSeeder(new PermissionCatalog($plugins)))->seed(new PdoAdapter($pdo), new DateTimeImmutable());
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln($missing === []
            ? '<info>No table to create. Seeded the permission catalog.</info>'
            : sprintf('<info>Created %d table(s): %s. Seeded the permission catalog.</info>', count($missing), implode(', ', array_column($missing, 'table'))));

        return Command::SUCCESS;
    }

    /**
     * Referenced tables before the tables referencing them; a reference to a table that already
     * exists is satisfied.
     * ponytail: mirrors SqlSchema::ordered() (private); polaris/pdo's createMissing() replaces it (#111).
     *
     * @param list<Model> $models
     * @return list<Model>
     */
    private static function ordered(array $models): array
    {
        $pending = array_column($models, 'table');
        $ordered = [];
        while ($models !== []) {
            $before = count($models);
            foreach ($models as $index => $model) {
                $waiting = array_filter($model->references, static fn($reference): bool => $reference->referencedTable !== $model->table && in_array($reference->referencedTable, $pending, true));
                if ($waiting === []) {
                    $ordered[] = $model;
                    $pending = array_values(array_filter($pending, static fn(string $table): bool => $table !== $model->table));
                    unset($models[$index]);
                }
            }
            if (count($models) === $before) {
                throw new RuntimeException('Circular foreign keys between the missing tables.');
            }
        }

        return $ordered;
    }
}
