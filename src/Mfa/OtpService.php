<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Event\OtpChallengeSent;
use Univeros\Polaris\Event\OtpVerifyFailed;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\OtpCooldownException;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\ClientContext;

use function in_array;
use function random_int;

/**
 * The SMS/email one-time-password engine: issue a code (challenge) and verify it.
 *
 * A code is a CSPRNG numeric string of `otp.length` digits, delivered out of band via the
 * {@see SmsSenderInterface}/{@see OtpMailerInterface} ports and stored only as a keyed HMAC
 * ({@see Pepper}, `otp` context) — never in plaintext. Each challenge is time-boxed
 * (`otp.ttl`), attempt-bounded (`otp.max_attempts`), and **single-use** (`consumed_at`): a verified
 * code cannot be replayed. Issuing a new code is throttled by the resend cooldown
 * (`otp.resend_cooldown`) and supersedes any older pending challenge so only the freshest is live.
 *
 * TOTP factors are verified live against their secret by {@see MfaTotpService}; this service is for
 * the sms/email channels only.
 */
final readonly class OtpService
{
    private const string PEPPER_CONTEXT = 'otp';

    /** Purposes a challenge may be scoped to; isolation keeps an `enroll` code from satisfying a `login_mfa` verify. */
    private const array VALID_PURPOSES = [
        OtpChallenge::PURPOSE_LOGIN_MFA,
        OtpChallenge::PURPOSE_ENROLL,
        OtpChallenge::PURPOSE_PASSWORD_RESET,
        OtpChallenge::PURPOSE_EMAIL_VERIFY,
        OtpChallenge::PURPOSE_STEP_UP,
    ];

    /**
     * @param RepositoryInterface<OtpChallenge> $challenges
     */
    public function __construct(
        private RepositoryInterface $challenges,
        private SmsSenderInterface $sms,
        private OtpMailerInterface $mailer,
        private Pepper $pepper,
        private OtpConfig $config,
        private UnitOfWorkInterface $unitOfWork,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * Issue (and send) a fresh OTP for an sms/email factor.
     *
     * @throws OtpCooldownException the resend cooldown has not yet elapsed
     */
    public function challenge(string $userId, MfaFactor $factor, string $purpose, ClientContext $client): OtpChallengeResult
    {
        $this->assertKnownPurpose($purpose);

        if (!in_array($factor->type, [MfaFactor::TYPE_SMS, MfaFactor::TYPE_EMAIL], true)) {
            throw new InvalidOtpException('OTP challenges apply only to sms/email factors.');
        }

        $now = $this->clock->now();
        $channel = $factor->type;
        $destination = $channel === MfaFactor::TYPE_SMS ? (string) $factor->phoneE164 : (string) $factor->email;
        if ($destination === '') {
            throw new InvalidOtpException('The factor has no destination to send a code to.');
        }

        $this->throttleAndSupersede($userId, $factor->id, $purpose, $now);

        $code = $this->generateCode();

        $challenge = new OtpChallenge();
        $challenge->id = Uuid::v7()->toRfc4122();
        $challenge->userId = $userId;
        $challenge->factorId = $factor->id;
        $challenge->purpose = $purpose;
        $challenge->channel = $channel;
        $challenge->codeHash = $this->pepper->hash(self::PEPPER_CONTEXT, $code);
        $challenge->destination = $destination;
        $challenge->maxAttempts = $this->config->maxAttempts;
        $challenge->expiresAt = $now->add(new DateInterval('PT' . $this->config->ttl . 'S'));
        $challenge->ip = $client->ip;
        $challenge->createdAt = $now;
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();

        $this->deliver($channel, $destination, $code);
        $this->events->dispatch(new OtpChallengeSent($userId, $factor->id, $channel));

        return new OtpChallengeResult($challenge->id, $channel, Destination::mask($channel, $destination));
    }

    /**
     * Verify a submitted code against the newest pending challenge, consuming it on success.
     *
     * @throws InvalidOtpException the code is wrong, expired, attempt-exhausted, or already used
     */
    public function verify(string $userId, string $factorId, #[SensitiveParameter] string $code, string $purpose): void
    {
        $this->assertKnownPurpose($purpose);

        $now = $this->clock->now();
        $challenge = $this->newestPending($userId, $factorId, $purpose, $now);

        // No live challenge, or its attempt budget is spent → the same generic failure as a wrong
        // code (no oracle for whether a challenge exists). The residual timing delta versus the
        // wrong-code path below (which writes) is bounded by the endpoint rate limit, as in
        // PasswordResetService. Concurrent verifies on one challenge can race the attempt counter
        // (a non-atomic ++); the per-account/token rate limit (#23) is the compensating control.
        if ($challenge === null || $challenge->attempts >= $challenge->maxAttempts) {
            throw new InvalidOtpException('The verification code is invalid.');
        }

        if (!$this->pepper->matches(self::PEPPER_CONTEXT, $code, (string) $challenge->codeHash)) {
            ++$challenge->attempts;
            $this->unitOfWork->persist($challenge);
            $this->unitOfWork->flush();
            $this->events->dispatch(new OtpVerifyFailed($userId, $factorId));

            throw new InvalidOtpException('The verification code is invalid.');
        }

        $challenge->consumedAt = $now;
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();
    }

    /**
     * @throws OtpCooldownException
     */
    private function throttleAndSupersede(string $userId, string $factorId, string $purpose, DateTimeImmutable $now): void
    {
        $newest = $this->newestPending($userId, $factorId, $purpose, $now);
        if (
            $newest !== null
            && ($now->getTimestamp() - $newest->createdAt->getTimestamp()) < $this->config->resendCooldown
        ) {
            throw new OtpCooldownException('Please wait before requesting another code.');
        }

        foreach ($this->pending($userId, $factorId, $purpose, $now) as $challenge) {
            $challenge->consumedAt = $now;
            $this->unitOfWork->persist($challenge);
        }
    }

    private function newestPending(string $userId, string $factorId, string $purpose, DateTimeImmutable $now): ?OtpChallenge
    {
        $newest = null;
        foreach ($this->pending($userId, $factorId, $purpose, $now) as $challenge) {
            if ($newest === null || $challenge->createdAt > $newest->createdAt) {
                $newest = $challenge;
            }
        }

        return $newest;
    }

    /**
     * Live challenges for the triple: unconsumed and not past expiry — an expired challenge neither
     * gates a resend (cooldown) nor satisfies a verify.
     *
     * @return list<OtpChallenge>
     */
    private function pending(string $userId, string $factorId, string $purpose, DateTimeImmutable $now): array
    {
        $pending = [];
        foreach ($this->challenges->findBy(['userId' => $userId, 'factorId' => $factorId, 'purpose' => $purpose]) as $challenge) {
            if ($challenge->consumedAt === null && $challenge->expiresAt > $now) {
                $pending[] = $challenge;
            }
        }

        return $pending;
    }

    /**
     * @param non-empty-string $destination
     */
    private function deliver(string $channel, string $destination, #[SensitiveParameter] string $code): void
    {
        if ($channel === MfaFactor::TYPE_SMS) {
            $this->sms->send($destination, "Your verification code is $code.");

            return;
        }

        $this->mailer->send($destination, 'otp_code', ['code' => $code, 'ttl' => $this->config->ttl]);
    }

    private function assertKnownPurpose(string $purpose): void
    {
        if (!in_array($purpose, self::VALID_PURPOSES, true)) {
            throw new InvalidOtpException('Unknown OTP purpose.');
        }
    }

    private function generateCode(): string
    {
        $code = '';
        for ($i = 0; $i < $this->config->length; ++$i) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }
}
