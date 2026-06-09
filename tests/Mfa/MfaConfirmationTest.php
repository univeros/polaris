<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Mfa\MfaConfirmation;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;

final class MfaConfirmationTest extends TestCase
{
    public function testFirstConfirmationConfirmsIssuesCodesSetsDefaultAndEmits(): void
    {
        $factor = $this->factor();
        $events = new RecordingEventDispatcher();

        // findBy returns only this (still-unconfirmed) factor → it is the first.
        $codes = $this->confirmation(others: [$factor], events: $events)->complete($factor);

        self::assertCount(RecoveryCodeService::COUNT, $codes);
        self::assertNotNull($factor->confirmedAt);
        self::assertTrue($factor->isDefault);
        self::assertCount(1, $events->ofType(MfaEnrolled::class));
    }

    public function testSubsequentConfirmationConfirmsButIssuesNothing(): void
    {
        $factor = $this->factor();
        $existing = $this->factor(id: 'factor-0');
        $existing->confirmedAt = new DateTimeImmutable('@100');
        $events = new RecordingEventDispatcher();

        $codes = $this->confirmation(others: [$existing, $factor], events: $events)->complete($factor);

        self::assertSame([], $codes);
        self::assertNotNull($factor->confirmedAt, 'the factor is still confirmed');
        self::assertFalse($factor->isDefault, 'only the first factor becomes default');
        self::assertCount(0, $events->ofType(MfaEnrolled::class));
    }

    /**
     * @param list<MfaFactor> $others
     */
    private function confirmation(array $others = [], ?RecordingEventDispatcher $events = null): MfaConfirmation
    {
        $clock = FrozenClock::at('2026-06-08 12:00:00');
        $unitOfWork = new RecordingUnitOfWork();

        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('findBy')->willReturn($others);

        return new MfaConfirmation(
            $factors,
            new RecoveryCodeService(
                new InMemoryRecoveryCodeRepository($unitOfWork),
                $unitOfWork,
                new Pepper('app-key-for-tests'),
                $clock,
                new RecordingEventDispatcher(),
            ),
            $unitOfWork,
            $clock,
            $events ?? new RecordingEventDispatcher(),
        );
    }

    private function factor(string $id = 'factor-1'): MfaFactor
    {
        $now = new DateTimeImmutable('2026-06-08 12:00:00');
        $factor = new MfaFactor();
        $factor->id = $id;
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_SMS;
        $factor->createdAt = $now;
        $factor->updatedAt = $now;

        return $factor;
    }
}
