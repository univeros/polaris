<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests;

use Altair\Container\Container;
use Altair\Module\Contracts\ModuleInterface;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Module;

final class ModuleTest extends TestCase
{
    public function testIsAUniverosModule(): void
    {
        $module = new Module();

        self::assertInstanceOf(ModuleInterface::class, $module);
        self::assertSame('univeros/polaris', $module->name());
    }

    public function testAppliesToAContainer(): void
    {
        $container = new Container();

        (new Module())->apply($container);

        self::assertTrue($container->has(Container::class));
    }
}
