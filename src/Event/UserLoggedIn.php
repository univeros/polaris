<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted on a completed login (`user.logged_in`) — password-only, or after the MFA gate.
 * `sessionId` is the new refresh family the access token is bound to; `amr` records how the
 * user authenticated (e.g. `["pwd"]`, `["pwd","otp"]`).
 */
final readonly class UserLoggedIn
{
    public const string NAME = 'user.logged_in';

    /**
     * @param list<string> $amr
     */
    public function __construct(
        public string $userId,
        public string $sessionId,
        public ?string $ip = null,
        public ?string $userAgent = null,
        public array $amr = ['pwd'],
    ) {
    }
}
