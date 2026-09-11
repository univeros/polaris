<?php

declare(strict_types=1);

namespace Univeros\Polaris\Console;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use PDO;
use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Symfony\Component\Console\Command\Command;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Database\Connection;
use Univeros\Polaris\Module;

/**
 * The six `polaris/cli` commands as `polaris:*`, on the module's bindings: the connection the
 * schema commands and the doctor inspect is the one Polaris runs on (a bound `PDO`, the framework's
 * `DatabaseSettings`, or the environment), the secrets and auth settings the ones the module builds
 * Polaris from. `univeros/cli` discovers `#[Command]` classes by directory and has no module hook,
 * so the application's `bin/altair` adds these to its `Altair\Cli\Application`.
 */
final class Commands
{
    /**
     * @return list<Command>
     */
    public static function all(Container $container, ?Env $env = null): array
    {
        $env ??= Module::env($container);
        $connection = static fn(): PDO => Connection::fromContainer($container, $env);
        $secrets = static fn(): Secrets => PolarisConfig::secrets($container, $env);
        $auth = static fn(): AuthConfig => PolarisConfig::auth($container, $env);

        $commands = [
            new SchemaExportCommand(),
            new SchemaCreateCommand($connection),
            new SchemaDropCommand($connection),
            new SchemaDiffCommand($connection),
            new ManifestCommand(),
            new DoctorCommand($secrets, $auth, $connection),
        ];
        foreach ($commands as $command) {
            $command->setName('polaris:' . $command->getName());
        }

        return $commands;
    }
}
