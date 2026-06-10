<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a session is re-scoped to a different organization (`auth.org_switched`).
 * `fromOrganizationId` is the session's previous org context (null for a session that had none).
 */
final readonly class OrganizationSwitched
{
    public const string NAME = 'auth.org_switched';

    public function __construct(
        public string $userId,
        public ?string $fromOrganizationId,
        public string $toOrganizationId,
    ) {
    }
}
