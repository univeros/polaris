<?php

declare(strict_types=1);

// The `--bootstrap` default of the polaris/cli commands once the application configures plugins
// (Commands::all()): the application's Polaris, so they see the plugins' tables, routes and permissions.

return \Univeros\Polaris\Console\Commands::polaris();
