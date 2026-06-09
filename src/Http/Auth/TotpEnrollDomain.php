<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Persistence\UserRepository;

/**
 * `POST /auth/mfa/totp/enroll` — start authenticator-app enrollment for the authenticated user:
 * returns the (unconfirmed) factor id, the base32 secret and `otpauth://` URI for manual/scan
 * setup, and a rendered QR. The secret is shown only here, until the factor is confirmed.
 */
final class TotpEnrollDomain extends AuthDomain
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly MfaTotpService $service,
    ) {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        $user = $userId === '' ? null : $this->users->find($userId);
        if (!$user instanceof User) {
            return $this->unauthorized();
        }

        $result = $this->service->enroll($user);

        return $this->respond(200, [
            'data' => [
                'factor_id' => $result->factorId,
                'secret' => $result->secret,
                'otpauth_uri' => $result->otpauthUri,
                'qr_svg' => $result->qrSvg,
            ],
        ]);
    }
}
