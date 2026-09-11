<?php

declare(strict_types=1);

use App\AppModule;
use Univeros\Polaris\Module;

/*
 * Modules installed in this app. The application's own module binds the demo mailbox and the
 * authentication of `/app/*` before Polaris builds itself from what the container binds; the
 * Polaris module contributes the 52 endpoints, the migration and the token bridge.
 *
 * @return list<Altair\Module\Contracts\ModuleInterface>
 */
return [
    new AppModule(dirname(__DIR__)),
    new Module(),
];
