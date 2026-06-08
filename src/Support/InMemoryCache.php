<?php

declare(strict_types=1);

namespace Univeros\Polaris\Support;

use DateInterval;
use DateTimeImmutable;
use Override;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Exception\CacheInvalidArgumentException;

use function preg_match;
use function time;

/**
 * A minimal in-process PSR-16 cache, backed by a plain array with per-entry TTL.
 *
 * Polaris binds this as the default {@see CacheInterface} only when the host has not bound
 * one, so the module — and its {@see \Univeros\Polaris\Http\Middleware\AuthRateLimitMiddleware}
 * — boots out of the box.
 *
 * **Not for production rate limiting.** PHP is share-nothing: each worker process holds its
 * own array, and it is discarded at the end of every request, so counters never accumulate
 * across requests or workers. A production host MUST bind a shared backend (Redis / APCu /
 * Memcached) for the limiter to be effective. This implementation is correct and sufficient
 * for the in-process functional test harness, where a single instance lives across the
 * requests of one test, and for single-process dev servers.
 */
final class InMemoryCache implements CacheInterface
{
    /** PSR-16 reserves these characters in keys; an implementation must reject them. */
    private const string RESERVED_KEY_CHARACTERS = '{}()/\\@:';

    /** @var array<string, array{value: mixed, expiresAt: int|null}> */
    private array $store = [];

    #[Override]
    public function get(string $key, mixed $default = null): mixed
    {
        $this->assertValidKey($key);

        if (!$this->isFresh($key)) {
            return $default;
        }

        return $this->store[$key]['value'];
    }

    #[Override]
    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->assertValidKey($key);

        $seconds = $this->ttlInSeconds($ttl);
        if ($seconds !== null && $seconds <= 0) {
            // An already-expired TTL stores nothing (and evicts any prior value).
            unset($this->store[$key]);

            return true;
        }

        $this->store[$key] = [
            'value' => $value,
            'expiresAt' => $seconds === null ? null : time() + $seconds,
        ];

        return true;
    }

    #[Override]
    public function delete(string $key): bool
    {
        $this->assertValidKey($key);
        unset($this->store[$key]);

        return true;
    }

    #[Override]
    public function clear(): bool
    {
        $this->store = [];

        return true;
    }

    /**
     * @param iterable<string> $keys
     * @return array<string, mixed>
     */
    #[Override]
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /**
     * @param iterable<string, mixed> $values
     */
    #[Override]
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $stored = true;
        foreach ($values as $key => $value) {
            $stored = $this->set($key, $value, $ttl) && $stored;
        }

        return $stored;
    }

    /**
     * @param iterable<string> $keys
     */
    #[Override]
    public function deleteMultiple(iterable $keys): bool
    {
        $deleted = true;
        foreach ($keys as $key) {
            $deleted = $this->delete($key) && $deleted;
        }

        return $deleted;
    }

    #[Override]
    public function has(string $key): bool
    {
        $this->assertValidKey($key);

        return $this->isFresh($key);
    }

    /**
     * Whether the key is present and not past its expiry; evicts it if it has expired.
     */
    private function isFresh(string $key): bool
    {
        if (!isset($this->store[$key])) {
            return false;
        }

        $expiresAt = $this->store[$key]['expiresAt'];
        if ($expiresAt !== null && $expiresAt <= time()) {
            unset($this->store[$key]);

            return false;
        }

        return true;
    }

    private function ttlInSeconds(null|int|DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }

        if ($ttl instanceof DateInterval) {
            $now = new DateTimeImmutable();

            return $now->add($ttl)->getTimestamp() - $now->getTimestamp();
        }

        return $ttl;
    }

    /**
     * @throws CacheInvalidArgumentException when the key is empty or carries a reserved character
     */
    private function assertValidKey(string $key): void
    {
        if ($key === '') {
            throw new CacheInvalidArgumentException('A cache key must be a non-empty string.');
        }

        if (preg_match('/[' . preg_quote(self::RESERVED_KEY_CHARACTERS, '/') . ']/', $key) === 1) {
            throw new CacheInvalidArgumentException(
                "The cache key \"$key\" contains a character reserved by PSR-16 ({}()/\\@:).",
            );
        }
    }
}
