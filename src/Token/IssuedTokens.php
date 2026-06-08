<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use DateTimeImmutable;

/**
 * The result of issuing or refreshing a session: a short-lived access JWT and the
 * opaque refresh-token secret (returned to the client exactly once — only its hash is
 * stored). `sessionId` is the refresh `family_id`, tying the access token to a device.
 */
final readonly class IssuedTokens
{
    public function __construct(
        public string $accessToken,
        public string $refreshToken,
        public int $accessExpiresIn,
        public DateTimeImmutable $refreshExpiresAt,
        public string $sessionId,
    ) {
    }
}
