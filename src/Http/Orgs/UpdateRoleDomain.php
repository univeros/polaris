<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use InvalidArgumentException;
use Override;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\RoleService;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\RoleNotFoundException;

use function is_array;
use function is_string;

/**
 * `PATCH /orgs/{id}/roles/{roleId}` — update a role's name, description, and/or permission set
 * (the slug is immutable). System roles and the org's `owner` role are protected.
 *
 * Gated on `roles.manage` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the constraints to {@see RoleService::update()}.
 */
final class UpdateRoleDomain extends OrganizationDomain
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
        if ($this->deniesActiveOrg($token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $roleId = (string) $input->get('roleId');
        if ($roleId === '') {
            return $this->unprocessable(['A role id is required.']);
        }

        $name = $input->get('name');
        $description = $input->get('description');
        $rawKeys = $input->get('permission_keys');
        $permissionKeys = null;
        if ($rawKeys !== null) {
            $permissionKeys = $this->stringList($rawKeys);
            if ($permissionKeys === null) {
                return $this->unprocessable(['permission_keys must be an array of permission keys.']);
            }
        }

        try {
            $role = $this->roles->update(
                (string) $token->getMetadata('sub'),
                $organizationId,
                $roleId,
                is_string($name) ? $name : null,
                is_string($description) ? $description : null,
                $permissionKeys,
            );
        } catch (RoleNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        }

        return $this->respond(200, ['data' => $role]);
    }

    /**
     * @return list<string>|null the validated list, or null when the payload is not a string list
     */
    private function stringList(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }

        $strings = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                return null;
            }
            $strings[] = $item;
        }

        return $strings;
    }
}
