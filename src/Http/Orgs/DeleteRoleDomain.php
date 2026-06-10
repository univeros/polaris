<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\RoleService;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\RoleNotFoundException;

/**
 * `DELETE /orgs/{id}/roles/{roleId}` — delete a custom role; the DB cascade detaches it from all
 * memberships. System roles and the org's `owner` role are protected.
 *
 * Gated on `roles.manage` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation.
 */
final class DeleteRoleDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ROLES_MANAGE];

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
        if ($this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $roleId = (string) $input->get('roleId');
        if ($roleId === '') {
            return $this->unprocessable(['A role id is required.']);
        }

        try {
            $this->roles->delete((string) $token->getMetadata('sub'), $organizationId, $roleId);
        } catch (RoleNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['deleted' => true]]);
    }
}
