<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted on a successful password login (`user.logged_in`). `sessionId` is the new
 * refresh family the access token is bound to.
 */
final readonly class UserLoggedIn
{
    public const string NAME = 'user.logged_in';

    public function __construct(
        public string $userId,
        public string $sessionId,
        public ?string $ip = null,
    ) {
    }
}
