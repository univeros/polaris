<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\RoleService;

/**
 * `GET /orgs/{id}/roles` — list the organization's roles with their permission keys.
 *
 * Gated on `roles.read` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation.
 */
final class ListRolesDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ROLES_READ];

    public function __construct(private readonly RoleService $roles)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $organizationId = (string) $input->get('id');
        if ($this->deniesActiveOrg($token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        return $this->respond(200, ['data' => $this->roles->listRoles($organizationId)]);
    }
}
