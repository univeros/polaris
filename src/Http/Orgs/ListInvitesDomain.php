<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\InvitationService;
use Univeros\Polaris\Authorization\PermissionCatalog;

/**
 * `GET /orgs/{id}/invites` — list the organization's pending invitations.
 *
 * Gated on `members.invite` by the AuthorizationMiddleware (whoever may send invitations may see
 * the outstanding ones); this domain enforces cross-tenant isolation.
 */
final class ListInvitesDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_INVITE];

    public function __construct(private readonly InvitationService $invitations)
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

        return $this->respond(200, ['data' => $this->invitations->listPending($organizationId)]);
    }
}
