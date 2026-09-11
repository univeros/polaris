<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Container\Container;
use Altair\Module\Contracts\ModuleInterface;
use Override;

/**
 * Polaris for PHP as a Univeros module: authentication, MFA/OTP, organizations and RBAC from
 * `polaris/core`, wired into a Univeros host through this one class in `config/modules.php`.
 *
 * 2.0 work package 0 reduces the 1.x tree to the framework glue; the bindings, the middleware,
 * the migration and the console commands arrive in the following work packages.
 */
final class Module implements ModuleInterface
{
    #[Override]
    public function name(): string
    {
        return 'univeros/polaris';
    }

    #[Override]
    public function apply(Container $container): void
    {
    }
}
