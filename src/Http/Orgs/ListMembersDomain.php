<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\MembershipService;
use Univeros\Polaris\Authorization\PermissionCatalog;

/**
 * `GET /orgs/{id}/members` — list the organization's members with their roles.
 *
 * The AuthorizationMiddleware enforces `members.read`; this domain enforces cross-tenant isolation
 * (the path org must be the caller's active org, unless superadmin).
 */
final class ListMembersDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_READ];

    public function __construct(private readonly MembershipService $members)
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

        return $this->respond(200, ['data' => $this->members->listMembers($organizationId)]);
    }
}
