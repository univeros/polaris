<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidVerificationTokenException;
use Univeros\Polaris\Identity\EmailVerificationService;

use function trim;

/**
 * `POST /auth/email/verify` — confirms an email address from its token. Idempotent: a
 * token for an already-verified user still returns `200`. A bad/expired token returns a
 * generic `400` that reveals nothing about which condition failed.
 */
final class VerifyEmailDomain extends AuthDomain
{
    public function __construct(private readonly EmailVerificationService $verifications)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = trim((string) $input->get('token', ''));

        if ($token === '') {
            return $this->unprocessable(['A verification token is required.']);
        }

        try {
            $this->verifications->verify($token);
        } catch (InvalidVerificationTokenException) {
            return $this->respond(400, ['message' => 'The verification token is invalid or has expired.']);
        }

        return $this->respond(200, ['message' => 'Email verified.']);
    }
}
