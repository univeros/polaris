<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\MembershipService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\LastOwnerException;
use Univeros\Polaris\Exception\MemberNotFoundException;

/**
 * `DELETE /orgs/{id}/members/{userId}` — remove a member from the organization.
 *
 * Gated on `members.remove` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the owner-protection / last-owner invariants to {@see MembershipService}.
 */
final class RemoveMemberDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_REMOVE];

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
        if ($this->deniesActiveOrg($token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $targetUserId = (string) $input->get('userId');
        if ($targetUserId === '') {
            return $this->unprocessable(['A target user is required.']);
        }

        try {
            $this->members->removeMember((string) $token->getMetadata('sub'), $organizationId, $targetUserId);
        } catch (MemberNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (LastOwnerException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['removed' => true]]);
    }
}
