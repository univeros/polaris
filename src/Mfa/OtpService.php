<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Cycle\Database\Injection\Fragment;
use Cycle\ORM\ORMInterface;
use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;
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

use function hash;
use function in_array;
use function is_array;
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
        private CacheInterface $cache,
        private ?ORMInterface $orm = null,
    ) {
    }

    /**
     * Issue (and send) a fresh OTP for an sms/email factor.
     *
     * @throws OtpCooldownException the resend cooldown has not yet elapsed
     */
    public function challenge(string $userId, MfaFactor $factor, ChallengePurpose $purpose, ClientContext $client): OtpChallengeResult
    {
        if (!in_array($factor->type, [MfaFactor::TYPE_SMS, MfaFactor::TYPE_EMAIL], true)) {
            throw new InvalidOtpException('OTP challenges apply only to sms/email factors.');
        }

        $now = $this->clock->now();
        $channel = $factor->type;
        $destination = $channel === MfaFactor::TYPE_SMS ? (string) $factor->phoneE164 : (string) $factor->email;
        if ($destination === '') {
            throw new InvalidOtpException('The factor has no destination to send a code to.');
        }

        // Both guards run before anything is queued on the unit of work, so a throttled request
        // leaves no half-staged supersessions behind for an unrelated later flush to commit.
        $this->assertResendCooldown($userId, $factor->id, $purpose, $now);
        $this->assertSendQuota($userId, $destination);
        $this->supersedePending($userId, $factor->id, $purpose, $now);

        $code = $this->generateCode();

        $challenge = new OtpChallenge();
        $challenge->id = Uuid::v7()->toRfc4122();
        $challenge->userId = $userId;
        $challenge->factorId = $factor->id;
        $challenge->purpose = $purpose->value;
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
    public function verify(string $userId, string $factorId, #[SensitiveParameter] string $code, ChallengePurpose $purpose): void
    {
        $now = $this->clock->now();
        $challenge = $this->newestPending($userId, $factorId, $purpose, $now);

        // No live challenge, or its attempt budget is spent → the same generic failure as a wrong
        // code (no oracle for whether a challenge exists). The residual timing delta versus the
        // wrong-code path below (which writes) is bounded by the endpoint rate limit, as in
        // PasswordResetService.
        if ($challenge === null || $challenge->attempts >= $challenge->maxAttempts) {
            throw new InvalidOtpException('The verification code is invalid.');
        }

        if (!$this->pepper->matches(self::PEPPER_CONTEXT, $code, (string) $challenge->codeHash)) {
            // Computed before the attempt is spent, so it holds in both the CAS and the
            // in-memory branch (which increments the entity).
            $attemptsLeft = max(0, $challenge->maxAttempts - $challenge->attempts - 1);
            $this->spendAttempt($challenge);
            $this->events->dispatch(new OtpVerifyFailed($userId, $factorId, $attemptsLeft));

            throw new InvalidOtpException('The verification code is invalid.');
        }

        // Atomic compare-and-swap on consumed_at, like refresh rotation: of two concurrent
        // presentations of one correct code, exactly one consumes the challenge; the loser gets
        // the same generic failure as a replayed code. The entity flush below re-writes the
        // value the CAS just wrote (same instant) — idempotent, and it IS the consumption
        // write in the ORM-less test wiring.
        if (!$this->claimConsumption($challenge, $now)) {
            throw new InvalidOtpException('The verification code is invalid.');
        }

        $challenge->consumedAt = $now;
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();
    }

    /**
     * Count a failed verify against the challenge's attempt budget with a single conditional
     * UPDATE (`attempts < max_attempts` is enforced database-side, so concurrent failures cannot
     * race the counter past the budget). The in-memory wiring has no database to CAS against and
     * increments the entity directly.
     */
    private function spendAttempt(OtpChallenge $challenge): void
    {
        if ($this->orm === null) {
            ++$challenge->attempts;
            $this->unitOfWork->persist($challenge);
            $this->unitOfWork->flush();

            return;
        }

        $source = $this->orm->getSource(OtpChallenge::class);
        $source->getDatabase()->update(
            $source->getTable(),
            ['attempts' => new Fragment('attempts + 1')],
            ['id' => $challenge->id, 'attempts' => ['<' => $challenge->maxAttempts]],
        )->run();
    }

    /**
     * Claim the challenge for consumption with a single conditional UPDATE; false means another
     * request consumed it first.
     */
    private function claimConsumption(OtpChallenge $challenge, DateTimeImmutable $now): bool
    {
        if ($this->orm === null) {
            // In-memory test wiring has no database to CAS against; the entity-level
            // consumed check already ran in pending(). Production wiring passes the ORM.
            return true;
        }

        $source = $this->orm->getSource(OtpChallenge::class);
        $affected = $source->getDatabase()->update(
            $source->getTable(),
            ['consumed_at' => $now],
            ['id' => $challenge->id, 'consumed_at' => null],
        )->run();

        return $affected === 1;
    }

    /**
     * @throws OtpCooldownException the resend cooldown has not yet elapsed
     */
    private function assertResendCooldown(string $userId, string $factorId, ChallengePurpose $purpose, DateTimeImmutable $now): void
    {
        $newest = $this->newestPending($userId, $factorId, $purpose, $now);
        if (
            $newest !== null
            && ($now->getTimestamp() - $newest->createdAt->getTimestamp()) < $this->config->resendCooldown
        ) {
            throw new OtpCooldownException('Please wait before requesting another code.');
        }
    }

    /**
     * Retire every still-pending challenge so only the about-to-be-issued one is live. The stamps
     * are queued, not flushed — they commit atomically with the new challenge's insert.
     */
    private function supersedePending(string $userId, string $factorId, ChallengePurpose $purpose, DateTimeImmutable $now): void
    {
        foreach ($this->pending($userId, $factorId, $purpose, $now) as $challenge) {
            $challenge->consumedAt = $now;
            $this->unitOfWork->persist($challenge);
        }
    }

    /**
     * Cap OTP sends per account and per destination within `otp.send_window` so a caller cannot
     * OTP-bomb a victim's phone/inbox or run up SMS cost (spec §9). The window is **fixed**, anchored
     * on its first send (`start`, held in the cache value) — not the cache TTL, which would slide
     * forward on every write. The get-then-set is not atomic, so concurrent sends can race the
     * counter, but the per-challenge resend cooldown and the per-IP endpoint rate limit bound the
     * residual.
     *
     * @throws OtpCooldownException the per-account or per-destination send budget for the window is spent
     */
    private function assertSendQuota(string $userId, string $destination): void
    {
        // PSR-16 reserves `:` `{}()/\@` in keys, so namespace with dots; the id is a UUID and the
        // destination is hashed (hex), both reserved-char-free.
        $now = $this->clock->now()->getTimestamp();
        $account = $this->sendBudget('otp.send.acct.' . $userId, $now);
        $perDestination = $this->sendBudget('otp.send.dest.' . hash('sha256', $destination), $now);

        if ($account['count'] >= $this->config->sendMax || $perDestination['count'] >= $this->config->sendMax) {
            throw new OtpCooldownException('Too many verification codes requested. Please try again later.');
        }

        $this->commitSendBudget($account);
        $this->commitSendBudget($perDestination);
    }

    /**
     * The current fixed-window counter for a key: the count so far and the window's start instant. A
     * key whose window has elapsed (or never existed) opens a fresh one.
     *
     * @return array{key: string, count: int, start: int}
     */
    private function sendBudget(string $key, int $now): array
    {
        $entry = $this->cache->get($key);
        $start = is_array($entry) ? (int) ($entry['start'] ?? 0) : 0;
        $count = is_array($entry) ? (int) ($entry['count'] ?? 0) : 0;

        if ($now - $start >= $this->config->sendWindow) {
            return ['key' => $key, 'count' => 0, 'start' => $now];
        }

        return ['key' => $key, 'count' => $count, 'start' => $start];
    }

    /**
     * @param array{key: string, count: int, start: int} $budget
     */
    private function commitSendBudget(array $budget): void
    {
        $this->cache->set(
            $budget['key'],
            ['count' => $budget['count'] + 1, 'start' => $budget['start']],
            $this->config->sendWindow,
        );
    }

    private function newestPending(string $userId, string $factorId, ChallengePurpose $purpose, DateTimeImmutable $now): ?OtpChallenge
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
    private function pending(string $userId, string $factorId, ChallengePurpose $purpose, DateTimeImmutable $now): array
    {
        $pending = [];
        foreach ($this->challenges->findBy(['userId' => $userId, 'factorId' => $factorId, 'purpose' => $purpose->value]) as $challenge) {
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

    private function generateCode(): string
    {
        $code = '';
        for ($i = 0; $i < $this->config->length; ++$i) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }
}
