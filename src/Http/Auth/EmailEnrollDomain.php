<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Exception\OtpCooldownException;
use Univeros\Polaris\Mfa\OtpFactorService;
use Univeros\Polaris\Persistence\UserRepository;

use function strlen;
use function trim;

/**
 * `POST /auth/mfa/email/enroll {email?}` — start email factor enrollment. Defaults to the user's
 * account email when none is given; a supplied address must be a valid email. Creates an
 * unconfirmed factor and emails a code; confirm at `/auth/mfa/email/confirm`.
 */
final class EmailEnrollDomain extends AuthDomain
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly OtpFactorService $service,
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

        $email = trim((string) $input->get('email', ''));
        if ($email === '') {
            $email = $user->email;
        } elseif (strlen($email) > 320 || !$this->isEmail($email)) {
            // Bound to the RFC 5321 / column maximum so the sent address can't differ from the
            // stored one via DB truncation.
            return $this->unprocessable(['A valid email address is required.']);
        }

        try {
            $result = $this->service->enroll($user, MfaFactor::TYPE_EMAIL, $email, $this->client($input));
        } catch (OtpCooldownException) {
            return $this->respond(429, ['error' => 'rate_limited', 'message' => 'Please wait before requesting another code.']);
        }

        return $this->respond(200, [
            'data' => ['factor_id' => $result->factorId, 'destination' => $result->maskedDestination],
        ]);
    }
}
