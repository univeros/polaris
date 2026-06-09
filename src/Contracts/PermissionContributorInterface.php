<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

/**
 * Lets a host module extend the permission catalog with its own capability keys.
 *
 * Polaris owns only the identity/tenant permissions (see {@see \Univeros\Polaris\Authorization\PermissionCatalog}).
 * A host that needs, say, `billing.manage` implements this interface and registers it; the
 * {@see \Univeros\Polaris\Authorization\PermissionCatalog} merges the contributions, and the seed
 * migration writes them to `auth_permissions`. Contributed keys can then be attached to roles by
 * the host.
 */
interface PermissionContributorInterface
{
    /**
     * Permission keys this module contributes, mapped to their human-readable descriptions.
     *
     * @return array<string, string> map of permission key (`resource.action`) to description
     */
    public function permissions(): array;
}
