<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a role is deleted from an organization (`role.deleted`). The cascade has already
 * detached the role from every membership when this fires.
 */
final readonly class RoleDeleted
{
    public const string NAME = 'role.deleted';

    public function __construct(
        public string $organizationId,
        public string $roleId,
        public string $actorUserId,
    ) {
    }
}
