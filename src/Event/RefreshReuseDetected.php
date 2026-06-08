<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a refresh token that has already been rotated (revoked) is presented
 * again — the signature of a stolen-token replay. The whole token family is revoked
 * before this fires; listeners alert and audit (`auth.refresh_reuse_detected`).
 */
final readonly class RefreshReuseDetected
{
    public const string NAME = 'auth.refresh_reuse_detected';

    public function __construct(
        public string $userId,
        public string $familyId,
        public ?string $ip = null,
    ) {
    }
}
