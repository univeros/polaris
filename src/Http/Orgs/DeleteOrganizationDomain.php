<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\OrganizationService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Entity\Organization;
use Univeros\Polaris\Persistence\OrganizationRepository;

/**
 * `DELETE /orgs/{id}` — soft-delete the organization (`status=suspended`, emits `org.deleted`).
 *
 * Gated on `org.delete` (held only by owners) by the AuthorizationMiddleware and step-up-gated;
 * this domain enforces cross-tenant isolation. An already-deleted organization reads as not found.
 * Purge-per-retention is ops tooling, not this API.
 */
final class DeleteOrganizationDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ORG_DELETE];

    public function __construct(
        private readonly OrganizationRepository $organizations,
        private readonly OrganizationService $service,
    ) {
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

        $organization = $this->organizations->find($organizationId);
        if (!$organization instanceof Organization || $organization->status !== Organization::STATUS_ACTIVE) {
            return $this->notFound('The organization does not exist.');
        }

        $this->service->softDelete($organization, (string) $token->getMetadata('sub'));

        return $this->respond(200, ['data' => ['deleted' => true]]);
    }
}
