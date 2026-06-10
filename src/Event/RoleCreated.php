<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a custom role is created in an organization (`role.created`).
 */
final readonly class RoleCreated
{
    public const string NAME = 'role.created';

    public function __construct(
        public string $organizationId,
        public string $roleId,
        public string $actorUserId,
    ) {
    }
}
