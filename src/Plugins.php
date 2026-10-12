<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Polaris\Contract\Plugin;

use function array_values;

/**
 * The polaris plugins an application runs, in registration order: bound in `config/container.php`
 * (`$container->instance(Plugins::class, new Plugins(new PasskeyPlugin(...)))`) when a plugin needs
 * arguments only the host has, else named by `POLARIS_PLUGINS`. A bound list wins over the variable.
 */
final readonly class Plugins
{
    /** @var list<Plugin> */
    public array $plugins;

    public function __construct(Plugin ...$plugins)
    {
        $this->plugins = array_values($plugins);
    }
}
