<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an organization is soft-deleted (`org.deleted`): its status flips to `suspended`,
 * every member's org authority is gone on the next resolution, and the rows await the retention
 * purge (ops tooling).
 */
final readonly class OrganizationDeleted
{
    public const string NAME = 'org.deleted';

    public function __construct(
        public string $organizationId,
        public string $actorUserId,
    ) {
    }
}
