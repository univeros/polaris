<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Exception\OtpCooldownException;
use Univeros\Polaris\Http\Middleware\MfaTokenMiddleware;
use Univeros\Polaris\Identity\MfaLoginService;

use function trim;

/**
 * `POST /auth/mfa/challenge {factor_id}` — during login, send the OTP for an sms/email factor and
 * return its masked destination. Authenticated by the `login_mfa` ticket ({@see MfaTokenMiddleware}
 * attaches the user id), not an access token. TOTP factors take their code from the app, so a
 * challenge for one (or for any non-sendable factor) is a `422`.
 */
final class MfaChallengeDomain extends AuthDomain
{
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

        $factorId = trim((string) $input->get('factor_id', ''));
        if ($factorId === '') {
            return $this->unprocessable(['A factor id is required.']);
        }

        try {
            $result = $this->service->challenge($userId, $factorId, $this->client($input));
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (OtpCooldownException) {
            return $this->respond(429, [
                'error' => 'too_many_requests',
                'message' => 'Please wait before requesting another code.',
            ]);
        } catch (InvalidOtpException) {
            return $this->respond(422, [
                'error' => 'unsupported_factor',
                'message' => 'This factor does not use a sent challenge.',
            ]);
        }

        return $this->respond(200, [
            'data' => ['channel' => $result->channel, 'destination' => $result->maskedDestination],
        ]);
    }
}
