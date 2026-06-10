<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Users;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use LogicException;
use Override;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Exception\UserNotFoundException;
use Univeros\Polaris\Identity\UserAdminService;

/**
 * `POST /users/{id}/enable` — re-enable a disabled (or locked) account, clearing lockout counters.
 * Admin tooling: gated on `users.manage` by the AuthorizationMiddleware.
 */
final class EnableUserDomain extends UserDomain
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::USERS_MANAGE];

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
            $this->users->enable($this->actorId($token), (string) $input->get('id'));
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (LogicException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['status' => 'active']]);
    }
}
