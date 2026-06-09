<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaTotpService;

use function trim;

/**
 * `POST /auth/mfa/totp/confirm` — confirm a pending TOTP factor with a code from the authenticator.
 * On the user's first confirmed factor the response also carries the one-time recovery codes.
 */
final class TotpConfirmDomain extends AuthDomain
{
    public function __construct(private readonly MfaTotpService $service)
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
        if ($userId === '') {
            return $this->unauthorized();
        }

        $factorId = trim((string) $input->get('factor_id', ''));
        $code = trim((string) $input->get('code', ''));
        if ($factorId === '' || $code === '') {
            return $this->unprocessable(['A factor id and verification code are required.']);
        }

        try {
            $result = $this->service->confirm($userId, $factorId, $code);
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (InvalidOtpException) {
            return $this->respond(422, ['error' => 'invalid_code', 'message' => 'The verification code is invalid.']);
        }

        $data = ['status' => 'confirmed'];
        if ($result->recoveryCodes !== []) {
            $data['recovery_codes'] = $result->recoveryCodes;
        }

        return $this->respond(200, ['data' => $data]);
    }
}
