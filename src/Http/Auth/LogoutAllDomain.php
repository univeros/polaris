<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Identity\SessionService;

/**
 * `POST /auth/logout-all` — revoke every session for the authenticated user (e.g. after a
 * security scare). Emits `auth.sessions_revoked`.
 */
final class LogoutAllDomain extends AuthDomain
{
    public function __construct(private readonly SessionService $sessions)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '') {
            return $this->unauthorized();
        }

        $this->sessions->logoutAll($userId, $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'logged_out_all']]);
    }
}
