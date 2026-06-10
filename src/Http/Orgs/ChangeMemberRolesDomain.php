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

use function is_array;
use function is_string;

/**
 * `PATCH /orgs/{id}/members/{userId}/roles` — replace a member's roles.
 *
 * Gated on `members.update` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the role invariants (no escalation, owner protection, last-owner) to
 * {@see MembershipService}, mapping their exceptions to HTTP statuses.
 */
final class ChangeMemberRolesDomain extends OrganizationDomain
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
        if ($this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $targetUserId = (string) $input->get('userId');
        if ($targetUserId === '') {
            return $this->unprocessable(['A target user is required.']);
        }

        $roleSlugs = $this->roleSlugs($input->get('role_slugs'));
        if ($roleSlugs === null) {
            return $this->unprocessable(['role_slugs must be an array of role slugs.']);
        }

        try {
            $this->members->changeRoles((string) $token->getMetadata('sub'), $organizationId, $targetUserId, $roleSlugs);
        } catch (MemberNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (LastOwnerException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['user_id' => $targetUserId, 'roles' => $roleSlugs]]);
    }

    /**
     * @return list<string>|null the validated slugs, or null when the payload is not a string list
     */
    private function roleSlugs(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }

        $slugs = [];
        foreach ($value as $slug) {
            if (!is_string($slug)) {
                return null;
            }
            $slugs[] = $slug;
        }

        return $slugs;
    }
}
