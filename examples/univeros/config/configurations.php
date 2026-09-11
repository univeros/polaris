<?php

declare(strict_types=1);

use Altair\Configuration\EnvironmentConfiguration;
use Altair\Logging\Configuration\LoggingConfiguration;
use Altair\Persistence\Configuration\CycleOrmConfiguration;

/*
 * The Configuration chain applied to the container at boot: `.env` (loaded when the framework's
 * `Env` is first resolved; bin/setup creates the file), logging, then the ORM whose `DB_*`
 * settings Polaris shares.
 *
 * @return list<Altair\Configuration\Contracts\ConfigurationInterface>
 */
$env = dirname(__DIR__) . '/.env';

return [
    ...(is_file($env) ? [new EnvironmentConfiguration($env)] : []),
    new LoggingConfiguration(),
    new CycleOrmConfiguration(),
];
