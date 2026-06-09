<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Security\Contracts\EncrypterInterface;
use Altair\Security\Exception\DecryptException;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\User;
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
        private MfaConfirmation $confirmation,
        private UnitOfWorkInterface $unitOfWork,
        private ClockInterface $clock,
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
    public function confirm(string $userId, string $factorId, #[SensitiveParameter] string $code): MfaConfirmResult
    {
        $factor = $this->requireTotpFactor($userId, $factorId);
        $this->verifyCodeAndFence($factor, $code);

        // The shared confirmation tail flushes (marks confirmed, first-factor recovery codes + event).
        return new MfaConfirmResult($this->confirmation->complete($factor));
    }

    /**
     * Verify a TOTP code against an already-confirmed factor at **login** (the MFA gate) — same code
     * check and replay fence as {@see confirm()}, but it does not run the enrollment tail (no
     * recovery codes, no `mfa.enrolled`); it only records the consumed step.
     *
     * @throws MfaFactorNotFoundException the factor is unknown or not the caller's TOTP factor
     * @throws InvalidOtpException        the code is wrong, or a replay of an already-used step
     */
    public function verify(string $userId, string $factorId, #[SensitiveParameter] string $code): void
    {
        $factor = $this->requireTotpFactor($userId, $factorId);
        $this->verifyCodeAndFence($factor, $code);

        $factor->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($factor);
        $this->unitOfWork->flush();
    }

    /**
     * @throws MfaFactorNotFoundException
     */
    private function requireTotpFactor(string $userId, string $factorId): MfaFactor
    {
        $factor = $this->factors->find($factorId);
        if (!$factor instanceof MfaFactor || $factor->userId !== $userId || $factor->type !== MfaFactor::TYPE_TOTP) {
            throw new MfaFactorNotFoundException('MFA factor not found.');
        }

        return $factor;
    }

    /**
     * Decrypt the secret, match the code within the skew window, reject a replayed step, and record
     * the consumed step on the factor ({@see MfaFactor::$lastUsedAt}) — the shared core of confirm
     * and login verify. Persisting/flushing the stamped factor is the caller's responsibility.
     *
     * @throws InvalidOtpException the code is wrong (or undecryptable secret), or a replayed step
     */
    private function verifyCodeAndFence(MfaFactor $factor, #[SensitiveParameter] string $code): void
    {
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

        $factor->lastUsedAt = $this->clock->now()->setTimestamp($matchedAt);
    }
}
