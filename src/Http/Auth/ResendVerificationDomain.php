<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Identity\EmailVerificationService;

use function trim;

/**
 * `POST /auth/email/verify/resend` — re-issues an email-verification challenge. Always a
 * generic `202`; internally it reissues only for a known, still-unverified account.
 */
final class ResendVerificationDomain extends AuthDomain
{
    private const string GENERIC =
        'If the address is registered and unverified, a new verification message has been sent.';

    public function __construct(private readonly EmailVerificationService $verifications)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $email = trim((string) $input->get('email', ''));

        if ($email === '' || !$this->isEmail($email)) {
            return $this->unprocessable(['A valid email address is required.']);
        }

        $this->verifications->resend($email, $this->client($input));

        return $this->respond(202, ['message' => self::GENERIC]);
    }
}
