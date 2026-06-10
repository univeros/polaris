<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\InvitationService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Exception\InvitationNotFoundException;

/**
 * `DELETE /orgs/{id}/invites/{inviteId}` — revoke a pending invitation; its token becomes useless.
 *
 * Gated on `members.invite` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation (revoking another org's invitation is indistinguishable from an unknown one: 404).
 */
final class RevokeInviteDomain extends OrganizationDomain
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
        if ($this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $inviteId = (string) $input->get('inviteId');
        if ($inviteId === '') {
            return $this->unprocessable(['An invitation id is required.']);
        }

        try {
            $this->invitations->revoke($organizationId, $inviteId);
        } catch (InvitationNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['revoked' => true]]);
    }
}
