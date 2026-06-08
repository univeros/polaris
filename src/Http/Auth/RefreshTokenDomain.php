<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidGrantException;
use Univeros\Polaris\Token\TokenService;

use function trim;

/**
 * `POST /auth/token/refresh` — exchange a refresh token for a fresh pair (the refresh
 * token itself is the credential, so the route is public).
 *
 * Rotation and reuse detection live in {@see TokenService}; any failure (unknown,
 * expired, or replayed token) collapses to a generic `401 invalid_grant`.
 */
final class RefreshTokenDomain extends AuthDomain
{
    public function __construct(private readonly TokenService $tokens)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $refreshToken = trim((string) $input->get('refresh_token', ''));

        if ($refreshToken === '') {
            return $this->unprocessable(['A refresh token is required.']);
        }

        try {
            $tokens = $this->tokens->refresh($refreshToken, $this->client($input));
        } catch (InvalidGrantException) {
            return $this->respond(401, ['error' => 'invalid_grant', 'message' => 'The refresh token is invalid or expired.']);
        }

        return $this->respond(200, [
            'data' => [
                'access_token' => $tokens->accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $tokens->accessExpiresIn,
                'refresh_token' => $tokens->refreshToken,
            ],
        ]);
    }
}
