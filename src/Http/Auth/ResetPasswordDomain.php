<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidPasswordException;
use Univeros\Polaris\Exception\InvalidResetTokenException;
use Univeros\Polaris\Identity\PasswordResetService;

use function trim;

/**
 * `POST /auth/password/reset` — set a new password from a reset token. On success every
 * session is revoked (logout everywhere). A bad/expired token returns a generic `400`.
 */
final class ResetPasswordDomain extends AuthDomain
{
    public function __construct(private readonly PasswordResetService $passwords)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = trim((string) $input->get('token', ''));
        $newPassword = (string) $input->get('new_password', '');

        if ($token === '' || $newPassword === '') {
            return $this->unprocessable(['A token and new password are required.']);
        }

        try {
            $this->passwords->reset($token, $newPassword, $this->client($input));
        } catch (InvalidPasswordException $exception) {
            return $this->unprocessable($exception->violations);
        } catch (InvalidResetTokenException) {
            return $this->respond(401, ['error' => 'invalid_token', 'message' => 'The reset token is invalid or has expired.']);
        }

        return $this->respond(200, ['data' => ['status' => 'password_reset']]);
    }
}
