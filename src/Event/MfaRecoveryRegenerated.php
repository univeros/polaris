<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user regenerates their MFA recovery codes (`mfa.recovery_regenerated`), retiring
 * the prior batch. Carries only the user identifier — never the codes themselves — so audit and
 * notification listeners can react without ever touching plaintext.
 */
final readonly class MfaRecoveryRegenerated
{
    public const string NAME = 'mfa.recovery_regenerated';

    public function __construct(
        public string $userId,
    ) {
    }
}
