<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a member is removed from an organization (`member.removed`).
 */
final readonly class MemberRemoved
{
    public const string NAME = 'member.removed';

    public function __construct(
        public string $organizationId,
        public string $userId,
        public string $actorUserId,
    ) {
    }
}
