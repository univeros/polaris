<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a role's name, description, or permission set is changed (`role.updated`).
 */
final readonly class RoleUpdated
{
    public const string NAME = 'role.updated';

    public function __construct(
        public string $organizationId,
        public string $roleId,
        public string $actorUserId,
    ) {
    }
}
