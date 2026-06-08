<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\InvalidArgumentException;
use Univeros\Polaris\Support\InMemoryCache;

final class InMemoryCacheTest extends TestCase
{
    public function testStoresAndFetchesAValue(): void
    {
        $cache = new InMemoryCache();

        self::assertTrue($cache->set('a', 1));
        self::assertSame(1, $cache->get('a'));
    }

    public function testReturnsTheDefaultOnAMiss(): void
    {
        $cache = new InMemoryCache();

        self::assertNull($cache->get('absent'));
        self::assertSame('fallback', $cache->get('absent', 'fallback'));
    }

    public function testHasReflectsPresence(): void
    {
        $cache = new InMemoryCache();
        $cache->set('a', 'v');

        self::assertTrue($cache->has('a'));
        self::assertFalse($cache->has('b'));
    }

    public function testDeleteRemovesAKey(): void
    {
        $cache = new InMemoryCache();
        $cache->set('a', 'v');

        self::assertTrue($cache->delete('a'));
        self::assertFalse($cache->has('a'));
    }

    public function testClearEmptiesEverything(): void
    {
        $cache = new InMemoryCache();
        $cache->set('a', 1);
        $cache->set('b', 2);

        self::assertTrue($cache->clear());
        self::assertFalse($cache->has('a'));
        self::assertFalse($cache->has('b'));
    }

    public function testMultipleOperations(): void
    {
        $cache = new InMemoryCache();

        self::assertTrue($cache->setMultiple(['a' => 1, 'b' => 2]));
        self::assertSame(['a' => 1, 'b' => 2, 'c' => 'x'], $cache->getMultiple(['a', 'b', 'c'], 'x'));
        self::assertTrue($cache->deleteMultiple(['a', 'b']));
        self::assertFalse($cache->has('a'));
        self::assertFalse($cache->has('b'));
    }

    public function testANonPositiveTtlStoresNothing(): void
    {
        $cache = new InMemoryCache();

        self::assertTrue($cache->set('a', 1, 0));
        self::assertFalse($cache->has('a'), 'a zero TTL is already expired');

        self::assertTrue($cache->set('b', 1, -5));
        self::assertFalse($cache->has('b'), 'a negative TTL is already expired');
    }

    public function testAPositiveTtlKeepsTheValueAvailable(): void
    {
        $cache = new InMemoryCache();

        $cache->set('a', 'v', 60);
        self::assertSame('v', $cache->get('a'));
    }

    public function testRejectsAnEmptyKey(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new InMemoryCache())->get('');
    }

    public function testRejectsAKeyWithReservedCharacters(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new InMemoryCache())->set('a{b}', 1);
    }
}
