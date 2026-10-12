<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Event;

use PHPUnit\Framework\TestCase;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Psr\EventDispatcher\StoppableEventInterface;
use stdClass;
use Univeros\Polaris\Event\ListenerDispatcher;

final class ListenerDispatcherTest extends TestCase
{
    public function testEveryListenerSeesEveryEventInOrderAndTheEventComesBack(): void
    {
        $seen = [];
        $listeners = [
            static function (object $event) use (&$seen): void {
                $seen[] = 'first';
            },
            static function (object $event) use (&$seen): void {
                $seen[] = 'second';
            },
        ];
        $dispatcher = new ListenerDispatcher(static fn(): array => $listeners);
        $event = new stdClass();

        self::assertSame($event, $dispatcher->dispatch($event));
        self::assertSame(['first', 'second'], $seen);
    }

    public function testTheListenersAreResolvedOnceOnTheFirstDispatch(): void
    {
        $resolved = 0;
        $dispatcher = new ListenerDispatcher(static function () use (&$resolved): array {
            ++$resolved;

            return [];
        });

        self::assertSame(0, $resolved);
        $dispatcher->dispatch(new stdClass());
        $dispatcher->dispatch(new stdClass());
        self::assertSame(1, $resolved);
    }

    public function testAStoppedEventGoesNoFurther(): void
    {
        $calls = 0;
        $listener = static function (object $event) use (&$calls): void {
            ++$calls;
        };
        $stopped = new class implements StoppableEventInterface {
            public function isPropagationStopped(): bool
            {
                return true;
            }
        };

        (new ListenerDispatcher(static fn(): array => [$listener, $listener]))->dispatch($stopped);

        self::assertSame(0, $calls);
    }

    public function testAfterThePolarisListenersTheEventGoesToTheHostsDispatcher(): void
    {
        $seen = [];
        $host = new RecordingEventDispatcher();
        $host->listen(static function (object $event) use (&$seen): void {
            $seen[] = 'host';
        });
        $listener = static function (object $event) use (&$seen): void {
            $seen[] = 'polaris';
        };

        (new ListenerDispatcher(static fn(): array => [$listener], $host))->dispatch(new stdClass());

        self::assertSame(['polaris', 'host'], $seen);
    }

    public function testAStoppedEventDoesNotReachTheHostsDispatcher(): void
    {
        $host = new RecordingEventDispatcher();
        $stopped = new class implements StoppableEventInterface {
            public function isPropagationStopped(): bool
            {
                return true;
            }
        };

        (new ListenerDispatcher(static fn(): array => [], $host))->dispatch($stopped);

        self::assertSame([], $host->events);
    }
}
