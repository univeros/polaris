<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Security\Contracts\EncrypterInterface;
use Altair\Security\Exception\DecryptException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;

/**
 * TOTP (authenticator-app) enrollment and confirmation.
 *
 * `enroll()` mints a base32 secret, stores it **encrypted at rest** on a new *unconfirmed* factor,
 * and returns the secret + `otpauth://` URI + QR for the app to scan (the secret is shown only
 * until confirmation). `confirm()` decrypts the secret, verifies the code within the configured
 * skew window, and on success marks the factor confirmed; the first confirmed factor becomes the
 * default and triggers a one-time batch of recovery codes plus `mfa.enrolled`.
 *
 * Replay defence: each verification records the matched TOTP time-step on the factor
 * ({@see MfaFactor::$lastUsedAt}); a code from that step or an earlier one is rejected, so an
 * observed code cannot be reused within its validity window.
 */
final readonly class MfaTotpService
{
    /**
     * @param RepositoryInterface<MfaFactor> $factors
     */
    public function __construct(
        private RepositoryInterface $factors,
        private TotpProviderInterface $totp,
        private EncrypterInterface $encrypter,
        private QrCodeRendererInterface $qr,
        private RecoveryCodeService $recoveryCodes,
        private UnitOfWorkInterface $unitOfWork,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    public function enroll(User $user): TotpEnrollResult
    {
        $now = $this->clock->now();
        $secret = $this->totp->generateSecret();

        $factor = new MfaFactor();
        $factor->id = Uuid::v7()->toRfc4122();
        $factor->userId = $user->id;
        $factor->type = MfaFactor::TYPE_TOTP;
        $factor->secretEncrypted = $this->encrypter->encrypt($secret);
        $factor->createdAt = $now;
        $factor->updatedAt = $now;
        $this->unitOfWork->persist($factor);
        $this->unitOfWork->flush();

        $uri = $this->totp->provisioningUri($secret, $user->email);

        return new TotpEnrollResult($factor->id, $secret, $uri, $this->qr->svg($uri));
    }

    /**
     * @throws MfaFactorNotFoundException the factor is unknown or not the caller's TOTP factor
     * @throws InvalidOtpException        the code is wrong, or a replay of an already-used step
     */
    public function confirm(string $userId, string $factorId, #[SensitiveParameter] string $code): TotpConfirmResult
    {
        $factor = $this->factors->find($factorId);
        if (!$factor instanceof MfaFactor || $factor->userId !== $userId || $factor->type !== MfaFactor::TYPE_TOTP) {
            throw new MfaFactorNotFoundException('MFA factor not found.');
        }

        try {
            $secret = (string) $this->encrypter->decrypt((string) $factor->secretEncrypted);
        } catch (DecryptException) {
            // A secret that can't be decrypted (corruption / key rotation) can't verify a code; treat
            // it as an invalid code rather than leaking an infrastructure error as a 500.
            throw new InvalidOtpException('The verification code is invalid.');
        }

        $matchedAt = $this->totp->matchingTimestamp($secret, $code);
        if ($matchedAt === null) {
            throw new InvalidOtpException('The verification code is invalid.');
        }

        if ($factor->lastUsedAt !== null && $matchedAt <= $factor->lastUsedAt->getTimestamp()) {
            throw new InvalidOtpException('The verification code has already been used.');
        }

        $now = $this->clock->now();
        $firstConfirmation = $factor->confirmedAt === null && !$this->hasOtherConfirmedFactor($userId, $factorId);

        if ($factor->confirmedAt === null) {
            $factor->confirmedAt = $now;
        }
        if ($firstConfirmation) {
            $factor->isDefault = true;
        }
        $factor->lastUsedAt = $now->setTimestamp($matchedAt);
        $factor->updatedAt = $now;
        $this->unitOfWork->persist($factor);

        $codes = $firstConfirmation ? $this->recoveryCodes->issue($userId) : [];

        $this->unitOfWork->flush();

        if ($firstConfirmation) {
            $this->events->dispatch(new MfaEnrolled($userId, $factorId));
        }

        return new TotpConfirmResult($codes);
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
