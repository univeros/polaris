<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user account is deleted/anonymized (`user.deleted`). The user id survives as a
 * tombstone — the row is kept (hashed email, nulled profile) for referential/audit integrity.
 */
final readonly class UserDeleted
{
    public const string NAME = 'user.deleted';

    public function __construct(
        public string $userId,
        public string $actorUserId,
    ) {
    }
}
