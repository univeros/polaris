<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidPasswordException;
use Univeros\Polaris\Identity\RegistrationService;

use function is_string;
use function mb_strlen;
use function trim;

/**
 * `POST /auth/register` — registers a user and triggers email verification.
 *
 * Always returns a generic `202` (anti-enumeration), except a `422` when input is invalid
 * or the password fails the policy (that is about the submitted input, not whether the
 * account exists).
 */
final class RegisterDomain extends AuthDomain
{
    /** Matches the `display_name` column width in {@see \Univeros\Polaris\Entity\User}. */
    private const int DISPLAY_NAME_MAX = 120;

    private const string GENERIC =
        'If the address can be registered, a verification message has been sent.';

    public function __construct(private readonly RegistrationService $registration)
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

        $displayName = $this->displayName($input);
        if ($displayName !== null && mb_strlen($displayName) > self::DISPLAY_NAME_MAX) {
            return $this->unprocessable(['The display name is too long.']);
        }

        try {
            $this->registration->register($email, $password, $displayName, $this->client($input));
        } catch (InvalidPasswordException $exception) {
            return $this->unprocessable($exception->violations);
        }

        return $this->respond(202, ['message' => self::GENERIC]);
    }

    private function displayName(InputCollection $input): ?string
    {
        $value = $input->get('display_name');
        if (!is_string($value)) {
            return null;
        }

        $trimmed = trim($value);

        return $trimmed === '' ? null : $trimmed;
    }
}
