<?php

declare(strict_types=1);

namespace Univeros\Polaris\Console;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Closure;
use LogicException;
use PDO;
use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\CommandProvider;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\Plugin;
use Polaris\Polaris;
use Polaris\Schema\Schema;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Command\Command;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Database\Connection;
use Univeros\Polaris\Module;

/**
 * The six `polaris/cli` commands as `polaris:*` and `polaris:schema:install-plugins`, on the module's
 * bindings, the configured plugins' tables included: the connection the
 * schema commands and the doctor inspect is the one Polaris runs on (a bound `PDO`, the framework's
 * `DatabaseSettings`, or the environment), the secrets and auth settings the ones the module builds
 * Polaris from. `univeros/cli` discovers `#[Command]` classes by directory and has no module hook,
 * so the application's `bin/altair` adds these to its `Altair\Cli\Application`.
 */
final class Commands
{
    /** ponytail: one application per process, as in `bin/altair`; the last `all()` wins. */
    private static ?Closure $polaris = null;

    /**
     * @return list<Command>
     */
    public static function all(Container $container, ?Env $env = null): array
    {
        $env ??= Module::env($container);
        $plugins = static fn(): array => PolarisConfig::plugins($container, $env);
        // The schema commands see the plugins' tables: register them before the connection is used.
        $connection = static function () use ($container, $env, $plugins): PDO {
            foreach ($plugins() as $plugin) {
                Schema::register(...$plugin->schema());
            }

            return Connection::fromContainer($container, $env);
        };
        $secrets = static fn(): Secrets => PolarisConfig::secrets($container, $env);
        $auth = static fn(): AuthConfig => PolarisConfig::auth($container, $env);

        // diff and drop see the plugins' tables through the connection and need no secrets; these four
        // learn the plugins' routes and permissions from the bootstrap.
        $bootstrapped = [new SchemaExportCommand(), new SchemaCreateCommand($connection), new ManifestCommand(), new DoctorCommand($secrets, $auth, $connection)];
        [$export, $create, $manifest, $doctor] = $bootstrapped;
        $commands = [$export, $create, new SchemaDropCommand($connection), new SchemaDiffCommand($connection), $manifest, $doctor];
        $configured = $plugins();
        if ($configured !== []) {
            // polaris/cli learns the plugins from a bootstrap returning the application's Polaris.
            self::$polaris = static fn(): Polaris => $container->get(Polaris::class);
            foreach ($bootstrapped as $command) {
                $command->getDefinition()->getOption('bootstrap')->setDefault(__DIR__ . '/bootstrap.php');
            }
            $commands = [...$commands, ...self::pluginCommands($container, $configured)];
        }
        foreach ($commands as $command) {
            $command->setName('polaris:' . $command->getName());
        }

        return [...$commands, new InstallPluginsCommand($connection, $plugins)];
    }

    /**
     * The application's Polaris, for `bootstrap.php`.
     */
    public static function polaris(): Polaris
    {
        if (self::$polaris === null) {
            throw new LogicException('Commands::all() has not registered the Polaris commands.');
        }

        return (self::$polaris)();
    }

    /**
     * Building their commands builds Polaris, so `bin/altair` needs the secrets once a plugin ships commands.
     *
     * @param list<Plugin> $plugins
     * @return list<Command>
     */
    private static function pluginCommands(Container $container, array $plugins): array
    {
        $commands = [];
        foreach ($plugins as $plugin) {
            if ($plugin instanceof CommandProvider) {
                $graph = $container->get(Graph::class);
                \assert($graph instanceof Graph);
                $commands = [...$commands, ...$plugin->commands($graph)];
            }
        }

        return $commands;
    }
}
