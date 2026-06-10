<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\RecoveryCode;
use Univeros\Polaris\Event\MfaRecoveryRegenerated;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;

/**
 * Exercises {@see RecoveryCodeService}'s verify/regenerate against a **real database driver**: codes
 * issued in one unit of work are matched, consumed (single-use), and regenerated through fresh
 * repository reads — proving the `auth_recovery_codes` query/stamp round-trips, not just the
 * in-memory logic the unit test covers.
 */
final class RecoveryCodeServicePersistenceTest extends DatabaseTestCase
{
    public function testVerifyConsumesACodeAndIsSingleUse(): void
    {
        $userId = Uuid::v7()->toRfc4122();
        $codes = $this->issueBatch($userId);

        self::assertTrue($this->service()->verify($userId, $codes[2]), 'a valid code authenticates');
        self::assertFalse($this->service()->verify($userId, $codes[2]), 'the same code cannot be reused');

        $this->unitOfWork->clear();
        self::assertSame(RecoveryCodeService::COUNT - 1, $this->service()->remaining($userId));
    }

    public function testVerifyRejectsAnUnknownCode(): void
    {
        $userId = Uuid::v7()->toRfc4122();
        $this->issueBatch($userId);

        self::assertFalse($this->service()->verify($userId, 'aaaaa-bbbbb'));
        self::assertSame(RecoveryCodeService::COUNT, $this->service()->remaining($userId));
    }

    public function testVerifyDoesNotMatchAnotherUsersCode(): void
    {
        $alice = Uuid::v7()->toRfc4122();
        $bob = Uuid::v7()->toRfc4122();
        $aliceCodes = $this->issueBatch($alice);
        $this->issueBatch($bob);

        self::assertFalse($this->service()->verify($bob, $aliceCodes[0]), 'codes are scoped to their owner in the database');
        self::assertTrue($this->service()->verify($alice, $aliceCodes[0]));
    }

    public function testRegenerateInvalidatesThePriorBatch(): void
    {
        $userId = Uuid::v7()->toRfc4122();
        $old = $this->issueBatch($userId);
        $events = new RecordingEventDispatcher();

        $fresh = $this->service($events)->regenerate($userId);
        $this->unitOfWork->clear();

        self::assertCount(RecoveryCodeService::COUNT, $fresh);
        self::assertSame(RecoveryCodeService::COUNT, $this->service()->remaining($userId), 'only the fresh batch is usable');
        self::assertFalse($this->service()->verify($userId, $old[0]), 'a prior-batch code no longer authenticates');
        self::assertTrue($this->service()->verify($userId, $fresh[0]), 'a fresh-batch code authenticates');
        self::assertCount(1, $events->ofType(MfaRecoveryRegenerated::class));
    }

    /**
     * Issue a batch and commit it so a subsequent {@see service()} reads it back from the database.
     *
     * @return list<string>
     */
    private function issueBatch(string $userId): array
    {
        $codes = $this->service()->issue($userId);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();

        return $codes;
    }

    private function service(?RecordingEventDispatcher $events = null): RecoveryCodeService
    {
        // The ORM is passed so verify() exercises the conditional-UPDATE spend (issue #97)
        // against the real driver, exactly as the production wiring does.
        return new RecoveryCodeService(
            new CycleRepository(RecoveryCode::class, $this->orm, $this->unitOfWork),
            $this->unitOfWork,
            new Pepper('app-key-for-tests-0123456789abcdef'),
            FrozenClock::at('2026-06-08 12:00:00'),
            $events ?? new RecordingEventDispatcher(),
            $this->orm,
        );
    }
}
