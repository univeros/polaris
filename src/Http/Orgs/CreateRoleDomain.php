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
use Univeros\Polaris\Exception\RoleSlugConflictException;

use function is_array;
use function is_string;

/**
 * `POST /orgs/{id}/roles` — create a custom role (`{name, slug, description?, permission_keys[]}`).
 *
 * Gated on `roles.manage` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the constraints (catalog-only keys, no keys above the actor's own
 * authority, unique slug) to {@see RoleService::create()}.
 */
final class CreateRoleDomain extends OrganizationDomain
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

        $name = $input->get('name');
        $slug = $input->get('slug');
        if (!is_string($name) || !is_string($slug)) {
            return $this->unprocessable(['A name and a slug are required.']);
        }

        $description = $input->get('description');
        $permissionKeys = $this->stringList($input->get('permission_keys'));
        if ($permissionKeys === null) {
            return $this->unprocessable(['permission_keys must be an array of permission keys.']);
        }

        try {
            $role = $this->roles->create(
                (string) $token->getMetadata('sub'),
                $organizationId,
                $name,
                $slug,
                is_string($description) ? $description : null,
                $permissionKeys,
            );
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        } catch (RoleSlugConflictException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        }

        return $this->respond(201, ['data' => $role]);
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
