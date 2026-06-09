<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Token\ClientContext;

use function in_array;

/**
 * Enrollment + confirmation for the OTP-delivered factor channels (SMS and email).
 *
 * `enroll()` creates an unconfirmed {@see MfaFactor} for the channel and issues an OTP via
 * {@see OtpService} (enroll purpose); `confirm()` verifies the submitted code through the same
 * service and then runs the shared {@see MfaConfirmation} tail (mark confirmed, first-factor
 * recovery codes + `mfa.enrolled`). The two channels differ only in the factor type, the
 * destination field, and which sender {@see OtpService} uses — so one service serves both.
 *
 * TOTP enrollment is {@see MfaTotpService}; the code-handling differs (a scanned secret vs a sent
 * code), but both share {@see MfaConfirmation}.
 */
final readonly class OtpFactorService
{
    /**
     * @param RepositoryInterface<MfaFactor> $factors
     */
    public function __construct(
        private RepositoryInterface $factors,
        private OtpService $otp,
        private MfaConfirmation $confirmation,
        private UnitOfWorkInterface $unitOfWork,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Create an unconfirmed SMS/email factor and send its first OTP.
     *
     * @param MfaFactor::TYPE_SMS|MfaFactor::TYPE_EMAIL $type
     * @param non-empty-string                          $destination the E.164 phone or email address
     */
    public function enroll(User $user, string $type, string $destination, ClientContext $client): OtpFactorEnrollResult
    {
        $now = $this->clock->now();

        // Cap pending enrollments: replace any still-unconfirmed factor of this channel so a user
        // can't accumulate unbounded unconfirmed rows (and OTP sends) by re-enrolling.
        foreach ($this->factors->findBy(['userId' => $user->id, 'type' => $type]) as $existing) {
            if ($existing->confirmedAt === null) {
                $this->unitOfWork->remove($existing);
            }
        }

        $factor = new MfaFactor();
        $factor->id = Uuid::v7()->toRfc4122();
        $factor->userId = $user->id;
        $factor->type = $type;
        if ($type === MfaFactor::TYPE_SMS) {
            $factor->phoneE164 = $destination;
        } else {
            $factor->email = $destination;
        }
        $factor->createdAt = $now;
        $factor->updatedAt = $now;
        $this->unitOfWork->persist($factor);
        $this->unitOfWork->flush();

        $challenge = $this->otp->challenge($user->id, $factor, OtpChallenge::PURPOSE_ENROLL, $client);

        return new OtpFactorEnrollResult($factor->id, $challenge->channel, $challenge->maskedDestination);
    }

    /**
     * @throws MfaFactorNotFoundException the factor is unknown or not the caller's sms/email factor
     * @throws InvalidOtpException        the code is wrong, expired, exhausted, or already used
     */
    public function confirm(string $userId, string $factorId, #[SensitiveParameter] string $code): MfaConfirmResult
    {
        $factor = $this->factors->find($factorId);
        if (
            !$factor instanceof MfaFactor
            || $factor->userId !== $userId
            || !in_array($factor->type, [MfaFactor::TYPE_SMS, MfaFactor::TYPE_EMAIL], true)
        ) {
            throw new MfaFactorNotFoundException('MFA factor not found.');
        }

        $this->otp->verify($userId, $factorId, $code, OtpChallenge::PURPOSE_ENROLL);

        $factor->lastUsedAt = $this->clock->now();

        return new MfaConfirmResult($this->confirmation->complete($factor));
    }
}
