<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Identity\SessionService;

use function trim;

/**
 * `DELETE /auth/sessions/{id}` — revoke a specific session of the authenticated user. A
 * session that does not belong to the caller returns `404` (no cross-user disclosure).
 */
final class RevokeSessionDomain extends AuthDomain
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
        $sessionId = trim((string) $input->get('id', ''));

        if ($userId === '') {
            return $this->unauthorized();
        }

        if ($sessionId === '') {
            return $this->unprocessable(['A session id is required.']);
        }

        if (!$this->sessions->revoke($userId, $sessionId)) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'Session not found.']);
        }

        return $this->respond(200, ['data' => ['status' => 'revoked']]);
    }
}
