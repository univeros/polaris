<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Http\Middleware\MfaTokenMiddleware;
use Univeros\Polaris\Identity\MfaLoginService;
use Univeros\Polaris\Token\IssuedTokens;

use function trim;

/**
 * `POST /auth/mfa/verify {factor_id?, code, type?}` — complete an MFA login. The code is checked
 * against the named factor (TOTP / sms / email) or, when `factor_id` is omitted or `type=recovery`,
 * against the user's recovery codes. On success the real access + refresh pair is minted (same shape
 * as a normal login). Authenticated by the `login_mfa` ticket ({@see MfaTokenMiddleware}).
 */
final class MfaVerifyDomain extends AuthDomain
{
    /** Sentinel `type` selecting the recovery-code path (no factor named). */
    private const string TYPE_RECOVERY = 'recovery';

    public function __construct(private readonly MfaLoginService $service)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $userId = (string) $input->get(MfaTokenMiddleware::ATTRIBUTE_MFA_USER_ID, '');
        if ($userId === '') {
            return $this->unauthorized();
        }

        $code = trim((string) $input->get('code', ''));
        if ($code === '') {
            return $this->unprocessable(['A verification code is required.']);
        }

        try {
            $tokens = $this->service->verify($userId, $this->factorId($input), $code, $this->client($input));
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (InvalidOtpException) {
            return $this->respond(422, ['error' => 'invalid_code', 'message' => 'The verification code is invalid.']);
        }

        return $this->respond(200, $this->body($tokens));
    }

    /**
     * The factor to verify against, or null for the recovery-code path — chosen when `type=recovery`
     * or no `factor_id` is supplied (spec §6).
     */
    private function factorId(InputCollection $input): ?string
    {
        if (trim((string) $input->get('type', '')) === self::TYPE_RECOVERY) {
            return null;
        }

        $factorId = trim((string) $input->get('factor_id', ''));

        return $factorId === '' ? null : $factorId;
    }

    /**
     * @return array<string, mixed>
     */
    private function body(IssuedTokens $tokens): array
    {
        return [
            'data' => [
                'access_token' => $tokens->accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $tokens->accessExpiresIn,
                'refresh_token' => $tokens->refreshToken,
            ],
        ];
    }
}
