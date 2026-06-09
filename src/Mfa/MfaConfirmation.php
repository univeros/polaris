<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Event\MfaEnrolled;

/**
 * The shared tail of confirming any MFA factor, regardless of channel.
 *
 * Once a factor's channel-specific verification has passed (TOTP code, SMS/email OTP, …), the
 * caller hands the factor here to be marked confirmed. The user's **first** confirmed factor
 * additionally becomes the default, mints a one-time batch of recovery codes, and emits
 * `mfa.enrolled` — so that "first factor ⇒ recovery codes + event" rule lives in exactly one place
 * instead of being duplicated per channel.
 *
 * @see MfaTotpService
 * @see OtpFactorService
 */
final readonly class MfaConfirmation
{
    /**
     * @param RepositoryInterface<MfaFactor> $factors
     */
    public function __construct(
        private RepositoryInterface $factors,
        private RecoveryCodeService $recoveryCodes,
        private UnitOfWorkInterface $unitOfWork,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * Mark the (already-verified) factor confirmed and return the recovery codes — non-empty only
     * when this is the user's first confirmed factor.
     *
     * @return list<string>
     */
    public function complete(MfaFactor $factor): array
    {
        $now = $this->clock->now();
        $firstConfirmation = $factor->confirmedAt === null
            && !$this->hasOtherConfirmedFactor($factor->userId, $factor->id);

        if ($factor->confirmedAt === null) {
            $factor->confirmedAt = $now;
        }
        if ($firstConfirmation) {
            $factor->isDefault = true;
        }
        $factor->updatedAt = $now;
        $this->unitOfWork->persist($factor);

        $codes = $firstConfirmation ? $this->recoveryCodes->issue($factor->userId) : [];

        $this->unitOfWork->flush();

        if ($firstConfirmation) {
            $this->events->dispatch(new MfaEnrolled($factor->userId, $factor->id));
        }

        return $codes;
    }

    private function hasOtherConfirmedFactor(string $userId, string $exceptFactorId): bool
    {
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->id !== $exceptFactorId && $factor->confirmedAt !== null) {
                return true;
            }
        }

        return false;
    }
}
