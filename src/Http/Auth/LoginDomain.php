<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\AccountDisabledException;
use Univeros\Polaris\Exception\EmailNotVerifiedException;
use Univeros\Polaris\Exception\InvalidCredentialsException;
use Univeros\Polaris\Identity\LoginResult;
use Univeros\Polaris\Identity\LoginService;

use function trim;

/**
 * `POST /auth/login` — password login (no-MFA path).
 *
 * Returns `200` with an access + refresh token pair on success. Credential and lock
 * failures collapse to an identical generic `401`; correct-credential account-state
 * failures return `403` (`account_disabled` or `email_unverified`).
 */
final class LoginDomain extends AuthDomain
{
    public function __construct(private readonly LoginService $login)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $email = trim((string) $input->get('email', ''));
        $password = (string) $input->get('password', '');

        if ($email === '' || $password === '') {
            return $this->unprocessable(['An email and password are required.']);
        }

        if (!$this->isEmail($email)) {
            return $this->unprocessable(['A valid email address is required.']);
        }

        try {
            $result = $this->login->login($email, $password, $this->client($input));
        } catch (EmailNotVerifiedException) {
            return $this->respond(403, [
                'error' => 'email_unverified',
                'message' => 'Verify your email address before logging in.',
                'resend' => '/auth/email/verify/resend',
            ]);
        } catch (AccountDisabledException) {
            return $this->respond(403, ['error' => 'account_disabled', 'message' => 'This account is disabled.']);
        } catch (InvalidCredentialsException) {
            return $this->respond(401, ['error' => 'invalid_credentials', 'message' => 'Invalid email or password.']);
        }

        return $this->respond(200, $this->body($result));
    }

    /**
     * @return array<string, mixed>
     */
    private function body(LoginResult $result): array
    {
        return [
            'data' => [
                'access_token' => $result->tokens->accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $result->tokens->accessExpiresIn,
                'refresh_token' => $result->tokens->refreshToken,
                'user' => [
                    'id' => $result->userId,
                    'email' => $result->email,
                    'email_verified' => $result->emailVerified,
                ],
            ],
        ];
    }
}
