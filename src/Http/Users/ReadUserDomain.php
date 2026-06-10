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
 * `GET /users/{id}` — read a user: yourself, or any user when holding `users.read` (admin scope).
 * Not permission-gated by the middleware because self-access must work without `users.read`; the
 * service enforces self-or-permission.
 */
final class ReadUserDomain extends UserDomain
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
            $user = $this->users->read($this->actorId($token), $this->actorOrg($token), (string) $input->get('id'));
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        }

        return $this->respond(200, ['data' => $user]);
    }
}
