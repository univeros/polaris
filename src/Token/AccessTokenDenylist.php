<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

use function is_int;

/**
 * Instant access-token revocation (`docs/auth/security.md` §3, `security.access_token.denylist`):
 * a logout-everywhere / disable / erase records a per-user revocation watermark in the cache, and
 * {@see \Univeros\Polaris\Http\Middleware\DenylistMiddleware} rejects any access token issued at
 * or before it — one cache read per request, no per-token bookkeeping.
 *
 * Entries live exactly one access-token TTL: after that every token they could affect has expired
 * on its own. A cache wipe therefore only shortens the window back to the stateless default.
 */
final class AccessTokenDenylist
{
    private const string KEY_PREFIX = 'polaris.denylist.user.';

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly int $accessTokenTtl,
    ) {
    }

    /**
     * Record that every access token of the user issued up to now is revoked.
     */
    public function revokeAllFor(string $userId): void
    {
        $this->cache->set(self::KEY_PREFIX . $userId, $this->clock->now()->getTimestamp(), $this->accessTokenTtl);
    }

    /**
     * Whether a token issued at the given time is inside the user's revocation watermark.
     */
    public function isRevoked(string $userId, DateTimeImmutable $issuedAt): bool
    {
        $watermark = $this->cache->get(self::KEY_PREFIX . $userId);

        return is_int($watermark) && $issuedAt->getTimestamp() <= $watermark;
    }
}
