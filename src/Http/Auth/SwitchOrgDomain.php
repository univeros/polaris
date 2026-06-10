<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Persistence\Contracts\RepositoryInterface;
use Override;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\Organization;
use Univeros\Polaris\Exception\InvalidGrantException;
use Univeros\Polaris\Token\TokenService;

use function is_string;

/**
 * `POST /auth/switch-org` — re-scope the current session to a different organization the caller is
 * an active member of, returning a fresh access token that carries that org's `org`/`roles`/`scope`.
 *
 * The live session's org context is re-pointed too, so subsequent refreshes stay scoped to the new
 * org. Requires an authenticated session (sub + sid from the access token); rejects switching to an
 * unknown org (404) or one the caller is not an active member of (403).
 */
final class SwitchOrgDomain extends AuthDomain
{
    /**
     * @param RepositoryInterface<Organization> $organizations
     * @param RepositoryInterface<Membership>   $memberships
     */
    public function __construct(
        private readonly TokenService $tokens,
        private readonly RepositoryInterface $organizations,
        private readonly RepositoryInterface $memberships,
        private readonly AuthConfig $config,
    ) {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        $sessionId = (string) $token->getMetadata('sid');
        if ($userId === '' || $sessionId === '') {
            return $this->unauthorized();
        }

        $organizationId = $input->get('organization_id');
        if (!is_string($organizationId) || $organizationId === '') {
            return $this->unprocessable(['An organization_id is required.']);
        }

        if (!$this->organizations->find($organizationId) instanceof Organization) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'The organization does not exist.']);
        }

        $membership = $this->memberships->findOneBy([
            'userId' => $userId,
            'organizationId' => $organizationId,
            'status' => Membership::STATUS_ACTIVE,
        ]);
        if (!$membership instanceof Membership) {
            return $this->respond(403, [
                'error' => 'forbidden',
                'message' => 'You are not an active member of that organization.',
            ]);
        }

        try {
            $accessToken = $this->tokens->switchOrganization($userId, $organizationId, $sessionId);
        } catch (InvalidGrantException) {
            return $this->respond(401, ['error' => 'session_ended', 'message' => 'The session is no longer active.']);
        }

        return $this->respond(200, [
            'data' => [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $this->config->accessToken->ttl,
                'org' => $organizationId,
            ],
        ]);
    }
}
