<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a membership's status changes (`member.status_changed`) — suspension or
 * reactivation; suspension also revokes the member's org-scoped sessions.
 */
final readonly class MemberStatusChanged
{
    public const string NAME = 'member.status_changed';

    public function __construct(
        public string $organizationId,
        public string $userId,
        public string $status,
        public string $actorUserId,
    ) {
    }
}
