<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\Gate;
use Univeros\Polaris\Authorization\MembershipService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\ResolvedAuthority;

/**
 * `GET /orgs/{id}/members` — list the organization's members with their roles.
 *
 * The AuthorizationMiddleware enforces `members.read`; this domain enforces cross-tenant isolation
 * (the path org must be the caller's active org, unless superadmin). Invited and suspended
 * members' emails are visible only to callers who also hold `members.invite` — a plain
 * `members.read` holder sees the active roster's emails but not those of people who have not
 * (or no longer) joined (issue #97).
 */
final class ListMembersDomain extends OrganizationDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_READ];

    public function __construct(private readonly MembershipService $members, private readonly Gate $gate)
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

        // The database-resolved authority the AuthorizationMiddleware attached; superadmins
        // resolve to the full catalog, so no separate exemption is needed.
        $authority = $input->get(ResolvedAuthority::class);
        $withPendingEmails = $authority instanceof ResolvedAuthority
            && $this->gate->allowsAuthority($authority, PermissionCatalog::MEMBERS_INVITE);

        return $this->respond(200, ['data' => $this->members->listMembers($organizationId, $withPendingEmails)]);
    }
}
