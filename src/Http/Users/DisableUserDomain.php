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
 * `POST /users/{id}/disable` — disable an account, revoking all its sessions. Admin tooling:
 * gated on `users.manage` by the AuthorizationMiddleware and step-up-gated; self-disablement is
 * refused (409) so an operator cannot lock themselves out mid-session.
 */
final class DisableUserDomain extends UserDomain
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
            $this->users->disable($this->actorId($token), (string) $input->get('id'));
        } catch (LogicException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['status' => 'disabled']]);
    }
}
