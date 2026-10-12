<?php

declare(strict_types=1);

namespace Univeros\Polaris\Doctor;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Doctor\Contracts\CheckInterface;
use Altair\Doctor\Result\CheckResult;
use Override;
use PDO;
use Polaris\Cli\Command\DoctorCommand;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Throwable;
use Univeros\Polaris\Bootstrap\PolarisConfig;
use Univeros\Polaris\Database\Connection;

use function trim;

/**
 * `polaris` in `bin/altair doctor`: what `polaris:doctor` checks (the secrets, the keys, the auth
 * settings, the database, the manifest), on the module's bindings.
 */
final readonly class PolarisCheck implements CheckInterface
{
    public function __construct(private Container $container, private Env $env)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'polaris';
    }

    #[Override]
    public function dependsOn(): array
    {
        return [];
    }

    #[Override]
    public function run(): CheckResult
    {
        $command = new DoctorCommand(
            fn(): Secrets => PolarisConfig::secrets($this->container, $this->env),
            fn(): AuthConfig => PolarisConfig::auth($this->container, $this->env),
            fn(): PDO => Connection::fromContainer($this->container, $this->env),
        );
        $output = new BufferedOutput();
        try {
            $code = $command->run(new ArrayInput([]), $output);
        } catch (Throwable $exception) {
            return CheckResult::error($this->name(), $exception->getMessage(), self::FIX);
        }

        return $code === 0
            ? CheckResult::ok($this->name(), 'Polaris is ready: secrets, keys, auth settings, database and manifest.')
            : CheckResult::error($this->name(), trim($output->fetch()), self::FIX);
    }

    private const string FIX = 'Run bin/altair polaris:doctor and set what it reports (APP_KEY, AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY, the database).';
}
