<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

/**
 * A system role template from the {@see PermissionCatalog}.
 *
 * Templates are seeded as system roles (`organization_id IS NULL`, `is_system = true`) and cloned
 * into org-scoped roles when an organization is created, so each tenant gets its own editable copy.
 * Immutable by construction.
 */
final readonly class RoleTemplate
{
    /**
     * @param list<string> $permissionKeys catalog permission keys this role grants
     */
    public function __construct(
        public string $slug,
        public string $name,
        public string $description,
        public array $permissionKeys,
    ) {
    }
}
