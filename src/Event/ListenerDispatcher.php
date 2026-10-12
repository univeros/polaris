<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use Closure;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\StoppableEventInterface;

/**
 * The PSR-14 dispatcher Polaris gets: every event goes to every Polaris listener
 * (`Polaris::listeners()`: the audit log, notifications, metrics, and every plugin's), resolved on
 * the first dispatch so the dispatcher can be handed to Polaris before Polaris exists, then to the
 * host's own dispatcher when it binds one, so its listeners see `UserRegistered` and the rest.
 */
final class ListenerDispatcher implements EventDispatcherInterface
{
    /** @var list<callable(object): void>|null */
    private ?array $listeners = null;

    /**
     * @param Closure(): list<callable(object): void> $provider
     */
    public function __construct(private readonly Closure $provider, private readonly ?EventDispatcherInterface $host = null)
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
        if ($event instanceof StoppableEventInterface && $event->isPropagationStopped()) {
            return $event;
        }

        return $this->host?->dispatch($event) ?? $event;
    }
}
