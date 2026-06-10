<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\RoleService;

/**
 * `GET /permissions` — the full permission catalog (Polaris core ∪ host-contributed), for building
 * role-management UIs.
 *
 * Authenticated but not permission-gated: the catalog is the same for every tenant and carries no
 * org data, and a member needs it to render role pickers.
 */
final class ListPermissionsDomain extends OrganizationDomain
{
    public function __construct(private readonly RoleService $roles)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        if ($this->token($input) === null) {
            return $this->unauthorized();
        }

        return $this->respond(200, ['data' => $this->roles->permissionCatalog()]);
    }
}
