<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use Closure;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\StoppableEventInterface;

/**
 * The PSR-14 dispatcher the module binds when the host binds none: every event goes to every
 * Polaris listener (`Polaris::listeners()`: the audit log, notifications, metrics), resolved on
 * the first dispatch so the dispatcher can be handed to Polaris before Polaris exists. A host
 * with its own dispatcher subscribes the listeners itself.
 */
final class ListenerDispatcher implements EventDispatcherInterface
{
    /** @var list<callable(object): void>|null */
    private ?array $listeners = null;

    /**
     * @param Closure(): list<callable(object): void> $provider
     */
    public function __construct(private readonly Closure $provider)
    {
    }

    #[Override]
    public function dispatch(object $event): object
    {
        foreach ($this->listeners ??= ($this->provider)() as $listener) {
            if ($event instanceof StoppableEventInterface && $event->isPropagationStopped()) {
                break;
            }
            $listener($event);
        }

        return $event;
    }
}
