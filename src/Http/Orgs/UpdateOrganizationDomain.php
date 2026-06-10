<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use InvalidArgumentException;
use Override;
use Univeros\Polaris\Authorization\OrganizationService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Entity\Organization;
use Univeros\Polaris\Persistence\OrganizationRepository;

use function is_string;

/**
 * `PATCH /orgs/{id}` — rename the organization.
 *
 * Gated on `org.update` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation. A soft-deleted organization reads as not found.
 */
final class UpdateOrganizationDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ORG_UPDATE];

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

        $name = $input->get('name');
        if (!is_string($name)) {
            return $this->unprocessable(['A name is required.']);
        }

        $organization = $this->organizations->find($organizationId);
        if (!$organization instanceof Organization || $organization->status !== Organization::STATUS_ACTIVE) {
            return $this->notFound('The organization does not exist.');
        }

        try {
            $organization = $this->service->update($organization, $name, (string) $token->getMetadata('sub'));
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
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
}
