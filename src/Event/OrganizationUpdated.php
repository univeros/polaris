<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an organization's profile is changed (`org.updated`).
 */
final readonly class OrganizationUpdated
{
    public const string NAME = 'org.updated';

    public function __construct(
        public string $organizationId,
        public string $actorUserId,
    ) {
    }
}
