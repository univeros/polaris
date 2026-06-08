<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Identity\SessionService;

/**
 * `POST /auth/logout` — revoke the caller's current session (the `sid` carried by its
 * access token). The stateless access token stays valid until it expires; the device can
 * no longer refresh.
 */
final class LogoutDomain extends AuthDomain
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

        // Fail closed: a token with no session (`sid`) cannot end a session, so don't
        // report a logout that revoked nothing.
        $sessionId = (string) $token->getMetadata('sid');
        if ($sessionId === '') {
            return $this->unauthorized();
        }

        $this->sessions->logout($sessionId);

        return $this->respond(200, ['data' => ['status' => 'logged_out']]);
    }
}
