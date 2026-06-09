<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when an MFA challenge is satisfied at the login gate (`mfa.verified`) and the real token
 * pair is about to be minted. Carries only identifiers — the user and which factor cleared the gate
 * (`null` for the recovery-code path) — never the code or secret.
 */
final readonly class MfaVerified
{
    public const string NAME = 'mfa.verified';

    public function __construct(
        public string $userId,
        public ?string $factorId = null,
    ) {
    }
}
