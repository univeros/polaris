<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Identity\SessionService;

/**
 * `GET /auth/sessions` — list the authenticated user's active sessions (devices), with the
 * calling session flagged `current` (matched by `sid`).
 */
final class SessionsDomain extends AuthDomain
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

        $currentSessionId = (string) $token->getMetadata('sid');

        return $this->respond(200, ['data' => ['sessions' => $this->sessions->listFor($userId, $currentSessionId)]]);
    }
}
