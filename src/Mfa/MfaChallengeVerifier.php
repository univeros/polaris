<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use SensitiveParameter;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Token\ClientContext;

use function in_array;

/**
 * The channel-agnostic core of satisfying an MFA factor: list a user's confirmed factors, issue a
 * per-channel challenge, and verify a submitted code (or a recovery code) — routing each to the
 * service that owns the factor type.
 *
 * It is purpose-parameterised so the same dispatch backs both the login gate
 * ({@see \Univeros\Polaris\Identity\MfaLoginService}, `login_mfa`) and step-up
 * ({@see \Univeros\Polaris\Identity\StepUpService}, `step_up`) without either re-implementing the
 * factor routing or replay rules. It performs no token minting and emits no events — the caller
 * wraps it with the policy for what a successful verification grants.
 */
final readonly class MfaChallengeVerifier
{
    /**
     * @param RepositoryInterface<MfaFactor> $factors
     */
    public function __construct(
        private RepositoryInterface $factors,
        private MfaTotpService $totp,
        private OtpService $otp,
        private RecoveryCodeService $recovery,
    ) {
    }

    /**
     * The user's confirmed factors — the only ones that can satisfy a challenge.
     *
     * @return list<MfaFactor>
     */
    public function confirmedFactors(string $userId): array
    {
        $confirmed = [];
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->confirmedAt !== null) {
                $confirmed[] = $factor;
            }
        }

        return $confirmed;
    }

    /**
     * Whether the user has at least one confirmed factor (so MFA — and step-up — apply to them).
     */
    public function hasConfirmedFactor(string $userId): bool
    {
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->confirmedAt !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * Issue and send an OTP for an sms/email factor under the given purpose, returning the masked
     * destination. TOTP and recovery codes have no server-sent code, so they are rejected.
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the factor type does not use a sent challenge
     */
    public function challenge(string $userId, string $factorId, string $purpose, ClientContext $client): OtpChallengeResult
    {
        $factor = $this->requireConfirmedFactor($userId, $factorId);
        if (!in_array($factor->type, [MfaFactor::TYPE_SMS, MfaFactor::TYPE_EMAIL], true)) {
            throw new InvalidOtpException('This factor does not require a challenge.');
        }

        return $this->otp->challenge($userId, $factor, $purpose, $client);
    }

    /**
     * Verify the code against the named factor — or, when none is named, against the user's recovery
     * codes — returning the factor id that cleared the gate (null for the recovery path).
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the code is wrong, expired, exhausted, or already used
     */
    public function verify(string $userId, ?string $factorId, #[SensitiveParameter] string $code, string $purpose): ?string
    {
        if ($factorId === null || $factorId === '') {
            if (!$this->recovery->verify($userId, $code)) {
                throw new InvalidOtpException('The verification code is invalid.');
            }

            return null;
        }

        $factor = $this->requireConfirmedFactor($userId, $factorId);
        match ($factor->type) {
            MfaFactor::TYPE_TOTP => $this->totp->verify($userId, $factorId, $code),
            MfaFactor::TYPE_SMS,
            MfaFactor::TYPE_EMAIL => $this->otp->verify($userId, $factorId, $code, $purpose),
            default => throw new MfaFactorNotFoundException('MFA factor not found.'),
        };

        return $factorId;
    }

    /**
     * @throws MfaFactorNotFoundException
     */
    private function requireConfirmedFactor(string $userId, string $factorId): MfaFactor
    {
        $factor = $this->factors->find($factorId);
        if (!$factor instanceof MfaFactor || $factor->userId !== $userId || $factor->confirmedAt === null) {
            throw new MfaFactorNotFoundException('MFA factor not found.');
        }

        return $factor;
    }
}
