<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use InvalidArgumentException;
use Override;
use Univeros\Polaris\Authorization\MembershipService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\LastOwnerException;
use Univeros\Polaris\Exception\MemberNotFoundException;

use function is_string;

/**
 * `PATCH /orgs/{id}/members/{userId}` — suspend or reactivate a member (`{"status": "active"|"suspended"}`).
 *
 * Gated on `members.update` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the invariants (owner protection, last-active-owner) and the org-scoped
 * session revocation on suspension to {@see MembershipService::changeStatus()}.
 */
final class ChangeMemberStatusDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_UPDATE];

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

        $status = $input->get('status');
        if (!is_string($status) || $status === '') {
            return $this->unprocessable(['status must be "active" or "suspended".']);
        }

        try {
            $this->members->changeStatus((string) $token->getMetadata('sub'), $organizationId, $targetUserId, $status);
        } catch (MemberNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (LastOwnerException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['user_id' => $targetUserId, 'status' => $status]]);
    }
}
