<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use SensitiveParameter;

use function count;

/**
 * The result of confirming an MFA factor (any channel). {@see $recoveryCodes} is non-empty only
 * when this confirm activated the user's first factor — the codes are returned **once** here and
 * only their hashes are stored.
 */
final readonly class MfaConfirmResult
{
    /**
     * @param list<string> $recoveryCodes
     */
    public function __construct(
        #[SensitiveParameter] public array $recoveryCodes = [],
    ) {
    }

    /**
     * Keep the one-time recovery codes out of var_dump/debug output; `#[SensitiveParameter]` only
     * covers stack traces.
     *
     * @return array<string, int>
     */
    public function __debugInfo(): array
    {
        return ['recoveryCodes' => count($this->recoveryCodes)];
    }
}
