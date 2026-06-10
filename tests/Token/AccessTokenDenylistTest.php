<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Token\AccessTokenDenylist;

/**
 * Verifies the #41 {@see AccessTokenDenylist}: a revocation watermarks the user for one access
 * TTL, tokens issued at or before the watermark read as revoked, tokens minted afterwards pass,
 * and an unmarked user is never revoked.
 */
final class AccessTokenDenylistTest extends TestCase
{
    public const string NOW = '2026-06-10 12:00:00';

    public function testWatermarkRevokesOlderTokensOnly(): void
    {
        $denylist = $this->denylist();
        $now = new DateTimeImmutable(self::NOW);

        $denylist->revokeAllFor('user-1');

        self::assertTrue($denylist->isRevoked('user-1', $now->sub(new DateInterval('PT5M'))));
        self::assertTrue($denylist->isRevoked('user-1', $now));
        self::assertFalse($denylist->isRevoked('user-1', $now->add(new DateInterval('PT1S'))));
    }

    public function testUnmarkedUsersAreNeverRevoked(): void
    {
        self::assertFalse($this->denylist()->isRevoked('user-1', new DateTimeImmutable(self::NOW)));
    }

    public function testEntriesExpireWithTheAccessTtl(): void
    {
        $cache = $this->arrayCache();
        $denylist = new AccessTokenDenylist($cache, $this->clock(), 900);

        $denylist->revokeAllFor('user-1');

        self::assertSame([900], $cache->ttls);
    }

    private function denylist(): AccessTokenDenylist
    {
        return new AccessTokenDenylist($this->arrayCache(), $this->clock(), 900);
    }

    private function clock(): ClockInterface
    {
        return new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable(AccessTokenDenylistTest::NOW);
            }
        };
    }

    /**
     * @return CacheInterface&object{ttls: list<int|null>}
     */
    private function arrayCache(): CacheInterface
    {
        return new class () implements CacheInterface {
            /** @var list<int|null> */
            public array $ttls = [];

            /** @var array<string, mixed> */
            private array $items = [];

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->items[$key] ?? $default;
            }

            public function set(string $key, mixed $value, mixed $ttl = null): bool
            {
                $this->items[$key] = $value;
                $this->ttls[] = $ttl instanceof \DateInterval ? -1 : $ttl;

                return true;
            }

            public function delete(string $key): bool
            {
                unset($this->items[$key]);

                return true;
            }

            public function clear(): bool
            {
                $this->items = [];

                return true;
            }

            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                foreach ($keys as $key) {
                    yield $key => $this->get($key, $default);
                }
            }

            public function setMultiple(iterable $values, mixed $ttl = null): bool
            {
                foreach ($values as $key => $value) {
                    $this->set($key, $value, $ttl);
                }

                return true;
            }

            public function deleteMultiple(iterable $keys): bool
            {
                foreach ($keys as $key) {
                    $this->delete($key);
                }

                return true;
            }

            public function has(string $key): bool
            {
                return isset($this->items[$key]);
            }
        };
    }
}
