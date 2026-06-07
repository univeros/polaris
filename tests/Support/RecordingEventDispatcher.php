<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_filter;
use function array_values;

/**
 * A PSR-14 dispatcher that records every dispatched event, so tests can assert which
 * domain events a service emitted.
 */
final class RecordingEventDispatcher implements EventDispatcherInterface
{
    /** @var list<object> */
    public array $events = [];

    #[Override]
    public function dispatch(object $event): object
    {
        $this->events[] = $event;

        return $event;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $type
     *
     * @return list<T>
     */
    public function ofType(string $type): array
    {
        return array_values(array_filter($this->events, static fn(object $event): bool => $event instanceof $type));
    }
}
