<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Users;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\UserNotFoundException;
use Univeros\Polaris\Identity\UserAdminService;

/**
 * `DELETE /users/{id}` — delete (anonymize) an account: yourself, or any user when holding
 * `users.manage`. Step-up-gated. The row survives as a tombstone (hashed email, nulled profile,
 * revoked sessions) for referential/audit integrity — the right-to-erasure flow of
 * `docs/auth/security.md` §9.
 */
final class DeleteUserDomain extends UserDomain
{
    public function __construct(private readonly UserAdminService $users)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        try {
            $this->users->erase($this->actorId($token), $this->actorOrg($token), (string) $input->get('id'));
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['deleted' => true]]);
    }
}
