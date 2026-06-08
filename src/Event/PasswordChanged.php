<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user's password is changed, by reset or by an authenticated change
 * (`user.password_changed`). Other sessions are revoked as part of the same operation.
 */
final readonly class PasswordChanged
{
    public const string NAME = 'user.password_changed';

    public const string METHOD_RESET = 'reset';
    public const string METHOD_CHANGE = 'change';

    public function __construct(
        public string $userId,
        public string $method,
    ) {
    }
}
