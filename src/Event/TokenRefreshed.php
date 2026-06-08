<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted after a successful refresh-token rotation: the presented token was consumed
 * and a new one issued in the same family (`auth.token_refreshed`).
 */
final readonly class TokenRefreshed
{
    public const string NAME = 'auth.token_refreshed';

    public function __construct(
        public string $userId,
        public string $familyId,
    ) {
    }
}
