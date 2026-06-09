<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user clears a step-up re-authentication (`mfa.step_up_completed`) and a refreshed
 * access token is minted for their existing session. Carries only identifiers — the user and the
 * session whose `auth_time` was refreshed — never the code. Failures surface as the shared
 * {@see MfaVerifyFailed}.
 */
final readonly class MfaStepUpCompleted
{
    public const string NAME = 'mfa.step_up_completed';

    public function __construct(
        public string $userId,
        public string $sessionId,
    ) {
    }
}
