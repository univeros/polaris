<?php

declare(strict_types=1);

namespace Univeros\Polaris\Event;

/**
 * Emitted when a user removes an MFA factor (`mfa.factor_removed`). Carries only identifiers so
 * audit/notification listeners can record the change without touching any secret.
 */
final readonly class MfaFactorRemoved
{
    public const string NAME = 'mfa.factor_removed';

    public function __construct(
        public string $userId,
        public string $factorId,
    ) {
    }
}
