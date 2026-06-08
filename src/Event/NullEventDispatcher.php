<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use Override;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A no-op PSR-14 dispatcher: the default until a host wires a real dispatcher and the
 * audit/notification listeners (Phase 4). It returns each event unchanged so domain
 * services can emit events unconditionally without a hard dependency on listener
 * infrastructure.
 */
final class NullEventDispatcher implements EventDispatcherInterface
{
    #[Override]
    public function dispatch(object $event): object
    {
        return $event;
    }
}
