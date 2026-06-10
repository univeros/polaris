<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a member's role set is replaced (`member.roles_changed`) — a privileged operation
 * that must leave an audit trail.
 */
final readonly class MemberRolesChanged
{
    public const string NAME = 'member.roles_changed';

    /**
     * @param list<string> $roleSlugs the member's new role set
     */
    public function __construct(
        public string $organizationId,
        public string $userId,
        public array $roleSlugs,
        public string $actorUserId,
    ) {
    }
}
