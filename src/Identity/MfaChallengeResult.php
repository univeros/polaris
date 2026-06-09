<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

/**
 * The outcome of a password login when the user has a confirmed MFA factor: no session is issued
 * yet. Instead the client receives a short-lived `login_mfa` ticket and the list of factors it may
 * use to complete the second step (spec §5). The real token pair is minted only after a successful
 * `/auth/mfa/verify`.
 *
 * This is the MFA-required sibling of {@see LoginResult}; {@see \Univeros\Polaris\Identity\LoginService}
 * returns one or the other.
 */
final readonly class MfaChallengeResult
{
    /**
     * @param list<MfaFactorView> $factors
     */
    public function __construct(
        public string $userId,
        public string $mfaToken,
        public array $factors,
    ) {
    }
}
