<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an invitation is accepted and the invitee's membership becomes active
 * (`member.joined`).
 */
final readonly class MemberJoined
{
    public const string NAME = 'member.joined';

    public function __construct(
        public string $organizationId,
        public string $userId,
        public string $email,
    ) {
    }
}
