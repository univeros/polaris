<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted after an organization is created and its creator granted the `owner` role
 * (`org.created`). Carries the new organization's id and slug and the owner's user id so audit
 * and provisioning listeners can react.
 */
final readonly class OrganizationCreated
{
    public const string NAME = 'org.created';

    public function __construct(
        public string $organizationId,
        public string $slug,
        public string $ownerUserId,
    ) {
    }
}
