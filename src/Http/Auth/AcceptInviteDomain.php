<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\InvitationService;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\InvalidInvitationTokenException;

use function is_string;

/**
 * `POST /auth/invites/accept` — accept an organization invitation from its emailed token.
 *
 * Authenticated but not permission-gated (the caller has no standing in the org yet). The service
 * enforces the email match (403 on mismatch) and single use; an unknown/consumed/expired token is
 * a uniform 400, mirroring email verification.
 */
final class AcceptInviteDomain extends AuthDomain
{
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

        $inviteToken = $input->get('token');
        if (!is_string($inviteToken) || $inviteToken === '') {
            return $this->unprocessable(['An invitation token is required.']);
        }

        try {
            $organizationId = $this->invitations->accept((string) $token->getMetadata('sub'), $inviteToken);
        } catch (InvalidInvitationTokenException $exception) {
            return $this->respond(400, ['message' => $exception->getMessage()]);
        } catch (AuthorizationException $exception) {
            return $this->respond(403, ['error' => 'forbidden', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['organization_id' => $organizationId]]);
    }
}
