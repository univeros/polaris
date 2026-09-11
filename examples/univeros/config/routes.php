<?php

declare(strict_types=1);

use App\Http\Actions\MeAction;
use App\Http\Actions\PingAction;

/*
 * The application's own route table: [METHOD, PATH, Action::class]. The Polaris routes are not
 * listed here: the module's PolarisMiddleware serves them before the dispatcher runs
 * (`bin/altair polaris:manifest` lists them).
 */
return [
    ['GET', '/ping', PingAction::class],
    ['GET', '/app/me', MeAction::class],
];
