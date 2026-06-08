<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use SensitiveParameter;

/**
 * Emitted when a password reset is requested (`user.password_reset_requested`): carries the
 * plaintext reset token for the mailer to deliver. Only the token's hash is stored, so
 * audit listeners must not record this field.
 */
final readonly class PasswordResetRequested
{
    public const string NAME = 'user.password_reset_requested';

    public function __construct(
        public string $userId,
        public string $email,
        #[SensitiveParameter] public string $resetToken,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['userId' => $this->userId, 'email' => $this->email, 'resetToken' => '[redacted]'];
    }
}
