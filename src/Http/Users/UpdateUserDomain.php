<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Users;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use InvalidArgumentException;
use Override;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\UserNotFoundException;
use Univeros\Polaris\Identity\UserAdminService;

use function is_string;

/**
 * `PATCH /users/{id}` — update a user's profile (display name): yourself, or any user when holding
 * `users.manage` (admin scope). Self-or-permission is enforced by the service.
 */
final class UpdateUserDomain extends UserDomain
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

        $displayName = $input->get('display_name');
        if ($displayName !== null && !is_string($displayName)) {
            return $this->unprocessable(['display_name must be a string.']);
        }

        try {
            $user = $this->users->updateProfile(
                $this->actorId($token),
                $this->actorOrg($token),
                (string) $input->get('id'),
                $displayName,
            );
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        }

        return $this->respond(200, ['data' => $user]);
    }
}
