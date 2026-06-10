<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Mfa\ChallengePurpose;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingOtpMailer;
use Univeros\Polaris\Tests\Support\RecordingSmsSender;

/**
 * Exercises {@see OtpService} verify against a **real database driver**, proving the conditional
 * UPDATE claims from issue #97 hold when the in-process entity is stale: the attempt counter is
 * bounded database-side (`attempts < max_attempts`) and consumption is a compare-and-swap on
 * `consumed_at` — the guards a concurrent request relies on, which the entity-level checks alone
 * cannot give.
 */
final class OtpServicePersistenceTest extends DatabaseTestCase
{
    private const string INSTANT = '2026-06-10 12:00:00';
    private const string APP_KEY = 'app-key-for-tests-0123456789abcdef';
    private const string CODE = '123456';

    public function testAWrongCodeCannotPushAttemptsPastTheBudgetWhenTheEntityIsStale(): void
    {
        $challenge = $this->seedChallenge();

        // Another worker exhausted the budget after this process loaded the row.
        $this->connection()->update('auth_otp_challenges', ['attempts' => $challenge->maxAttempts], ['id' => $challenge->id])->run();

        try {
            $this->service()->verify($challenge->userId, (string) $challenge->factorId, '000000', ChallengePurpose::LoginMfa);
            self::fail('Expected the wrong code to be rejected.');
        } catch (InvalidOtpException) {
            // expected
        }

        // The conditional UPDATE must not reset or exceed the exhausted budget (the old
        // entity-level ++ would have written stale attempts + 1 = 1, reopening the budget).
        $row = $this->connection()->query('SELECT attempts FROM auth_otp_challenges')->fetch();
        self::assertSame($challenge->maxAttempts, (int) $row['attempts']);
    }

    public function testACorrectCodeCannotConsumeAChallengeAlreadyConsumedConcurrently(): void
    {
        $challenge = $this->seedChallenge();

        // Another worker consumed the challenge after this process loaded the row.
        $this->connection()->update(
            'auth_otp_challenges',
            ['consumed_at' => new DateTimeImmutable(self::INSTANT)],
            ['id' => $challenge->id],
        )->run();

        $this->expectException(InvalidOtpException::class);

        $this->service()->verify($challenge->userId, (string) $challenge->factorId, self::CODE, ChallengePurpose::LoginMfa);
    }

    public function testACorrectCodeConsumesTheChallengeOnce(): void
    {
        $challenge = $this->seedChallenge();

        $this->service()->verify($challenge->userId, (string) $challenge->factorId, self::CODE, ChallengePurpose::LoginMfa);

        $row = $this->connection()->query('SELECT consumed_at FROM auth_otp_challenges')->fetch();
        self::assertNotNull($row['consumed_at'], 'the challenge is consumed in the database');
    }

    /**
     * Persist a live challenge for {@see CODE} and keep it in the heap, mirroring a request that
     * has loaded the row while a concurrent request mutates it.
     */
    private function seedChallenge(): OtpChallenge
    {
        $now = new DateTimeImmutable(self::INSTANT);

        $challenge = new OtpChallenge();
        $challenge->id = Uuid::v7()->toRfc4122();
        $challenge->userId = Uuid::v7()->toRfc4122();
        $challenge->factorId = Uuid::v7()->toRfc4122();
        $challenge->purpose = ChallengePurpose::LoginMfa->value;
        $challenge->channel = OtpChallenge::CHANNEL_SMS;
        $challenge->codeHash = (new Pepper(self::APP_KEY))->hash('otp', self::CODE);
        $challenge->destination = '+14155550101';
        $challenge->expiresAt = $now->modify('+5 minutes');
        $challenge->createdAt = $now->modify('-2 minutes'); // outside the resend cooldown
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();

        return $challenge;
    }

    private function service(): OtpService
    {
        return new OtpService(
            new CycleRepository(OtpChallenge::class, $this->orm, $this->unitOfWork),
            new RecordingSmsSender(),
            new RecordingOtpMailer(),
            new Pepper(self::APP_KEY),
            OtpConfig::fromArray([]),
            $this->unitOfWork,
            FrozenClock::at(self::INSTANT),
            new RecordingEventDispatcher(),
            new InMemoryCache(),
            $this->orm,
        );
    }
}
