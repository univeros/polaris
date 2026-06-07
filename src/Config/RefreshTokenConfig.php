<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;

/**
 * Refresh-token settings: lifetime, rotation, reuse detection, and optional sliding expiry.
 */
final readonly class RefreshTokenConfig
{
    public function __construct(
        public int $ttl,
        public bool $rotation,
        public bool $reuseDetection,
        public bool $sliding,
        public int $maxLifetime,
    ) {
        if ($ttl <= 0) {
            throw new InvalidConfigException('auth.refresh_token.ttl must be a positive integer.');
        }

        if ($maxLifetime < $ttl) {
            throw new InvalidConfigException('auth.refresh_token.max_lifetime must be >= ttl.');
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            ttl: (int) ($data['ttl'] ?? 2592000),
            rotation: (bool) ($data['rotation'] ?? true),
            reuseDetection: (bool) ($data['reuse_detection'] ?? true),
            sliding: (bool) ($data['sliding'] ?? false),
            maxLifetime: (int) ($data['max_lifetime'] ?? 7776000),
        );
    }
}
