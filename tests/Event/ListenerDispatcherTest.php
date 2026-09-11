<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Event;

use PHPUnit\Framework\TestCase;
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
}
