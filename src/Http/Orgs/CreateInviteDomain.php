<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use InvalidArgumentException;
use Override;
use Univeros\Polaris\Authorization\InvitationService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Exception\AlreadyMemberException;
use Univeros\Polaris\Exception\AuthorizationException;

use function filter_var;
use function is_array;
use function is_string;
use function strlen;

use const FILTER_VALIDATE_EMAIL;

/**
 * `POST /orgs/{id}/invites` — invite someone (who may not yet have an account) to the organization.
 *
 * Gated on `members.invite` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the invariants (no inviting an active member, no granting roles above
 * the inviter's authority) to {@see InvitationService::invite()}.
 */
final class CreateInviteDomain extends OrganizationDomain
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

        $email = $input->get('email');
        if (!is_string($email) || strlen($email) > 320 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return $this->unprocessable(['A valid email is required.']);
        }

        $roleSlugs = $this->roleSlugs($input->get('role_slugs'));
        if ($roleSlugs === null) {
            return $this->unprocessable(['role_slugs must be an array of role slugs.']);
        }

        try {
            $invitation = $this->invitations->invite(
                (string) $token->getMetadata('sub'),
                $organizationId,
                $email,
                $roleSlugs,
            );
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        } catch (AlreadyMemberException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        }

        return $this->respond(201, ['data' => $invitation]);
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
