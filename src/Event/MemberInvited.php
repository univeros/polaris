<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

use SensitiveParameter;

/**
 * Emitted when an organization invitation is created or re-issued (`member.invited`): carries
 * the plaintext invite token so the mailer listener can deliver the accept link. The token is
 * never persisted in plaintext — only its hash is stored — so audit listeners must not record
 * this field.
 */
final readonly class MemberInvited
{
    public const string NAME = 'member.invited';

    public function __construct(
        public string $organizationId,
        public string $email,
        public string $invitedBy,
        #[SensitiveParameter] public string $inviteToken,
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
            'organizationId' => $this->organizationId,
            'email' => $this->email,
            'invitedBy' => $this->invitedBy,
            'inviteToken' => '[redacted]',
        ];
    }
}
