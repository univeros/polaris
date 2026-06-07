<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use SensitiveParameter;

/**
 * Emitted after a new user is registered (and on a verification resend): carries the
 * plaintext email-verification token so the mailer listener can deliver the link/OTP
 * (`user.registered`). The token is never persisted in plaintext — only its hash is
 * stored — so audit listeners must not record this field.
 */
final readonly class UserRegistered
{
    public const string NAME = 'user.registered';

    public function __construct(
        public string $userId,
        public string $email,
        #[SensitiveParameter] public string $verificationToken,
    ) {
    }

    /**
     * Redact the token from var_dump/debug output. `#[SensitiveParameter]` only covers
     * stack traces, so this guards against accidental dumping of the event.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'userId' => $this->userId,
            'email' => $this->email,
            'verificationToken' => '[redacted]',
        ];
    }
}
