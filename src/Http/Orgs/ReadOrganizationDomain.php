<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Persistence\Contracts\RepositoryInterface;
use Override;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Entity\Organization;

use function in_array;
use function is_array;

/**
 * `GET /orgs/{id}` — read a single organization.
 *
 * The {@see \Univeros\Polaris\Http\Middleware\AuthorizationMiddleware} enforces the declared
 * `org.read` permission for the caller's active org. This domain then enforces **cross-tenant
 * isolation**: the requested `{id}` must equal the caller's active org (the token's `org` claim) —
 * a token scoped to org A cannot read org B — unless the caller is a `superadmin`, who may read any.
 */
final class ReadOrganizationDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ORG_READ];

    /**
     * @param RepositoryInterface<Organization> $organizations
     */
    public function __construct(private readonly RepositoryInterface $organizations)
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
        if ($organizationId === '') {
            return $this->notFound();
        }

        $roles = $token->getMetadata('roles');
        $isSuperadmin = is_array($roles) && in_array(PermissionCatalog::ROLE_SUPERADMIN, $roles, true);
        if (!$isSuperadmin && $organizationId !== $token->getMetadata('org')) {
            return $this->respond(403, [
                'error' => 'forbidden',
                'message' => 'That organization is not your active organization.',
            ]);
        }

        $organization = $this->organizations->find($organizationId);
        if (!$organization instanceof Organization) {
            return $this->notFound();
        }

        return $this->respond(200, [
            'data' => [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
                'status' => $organization->status,
            ],
        ]);
    }

    private function notFound(): PayloadInterface
    {
        return $this->respond(404, ['error' => 'not_found', 'message' => 'The organization does not exist.']);
    }
}
