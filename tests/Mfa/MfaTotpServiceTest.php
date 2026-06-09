<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Security\Contracts\EncrypterInterface;
use Altair\Security\Exception\DecryptException;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaConfirmation;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;

final class MfaTotpServiceTest extends TestCase
{
    public function testConfirmRejectsAnUnknownFactor(): void
    {
        $this->expectException(MfaFactorNotFoundException::class);

        $this->service(null)->confirm('user-1', 'missing', '123456');
    }

    public function testConfirmRejectsAFactorOwnedByAnotherUser(): void
    {
        $this->expectException(MfaFactorNotFoundException::class);

        $this->service($this->factor(userId: 'someone-else'))->confirm('user-1', 'factor-1', '123456');
    }

    public function testConfirmRejectsANonTotpFactor(): void
    {
        $this->expectException(MfaFactorNotFoundException::class);

        $this->service($this->factor(type: MfaFactor::TYPE_SMS))->confirm('user-1', 'factor-1', '123456');
    }

    public function testConfirmRejectsAnInvalidCode(): void
    {
        $this->expectException(InvalidOtpException::class);

        $this->service($this->factor(), matched: null)->confirm('user-1', 'factor-1', '000000');
    }

    public function testConfirmRejectsAReplayedStep(): void
    {
        $factor = $this->factor();
        $factor->lastUsedAt = (new DateTimeImmutable('@1000'));

        $this->expectException(InvalidOtpException::class);

        // The matched step equals the last-used step → replay.
        $this->service($factor, matched: 1000)->confirm('user-1', 'factor-1', '123456');
    }

    public function testADecryptFailureIsTreatedAsAnInvalidCode(): void
    {
        $encrypter = $this->createStub(EncrypterInterface::class);
        $encrypter->method('decrypt')->willThrowException(new DecryptException('corrupt'));

        $this->expectException(InvalidOtpException::class);

        $this->service($this->factor(), encrypter: $encrypter)->confirm('user-1', 'factor-1', '123456');
    }

    public function testFirstConfirmationConfirmsIssuesCodesAndEmitsTheEvent(): void
    {
        $factor = $this->factor();
        $events = new RecordingEventDispatcher();

        $result = $this->service($factor, matched: 5000, others: [$factor], events: $events)
            ->confirm('user-1', 'factor-1', '123456');

        self::assertCount(RecoveryCodeService::COUNT, $result->recoveryCodes);
        self::assertNotNull($factor->confirmedAt);
        self::assertTrue($factor->isDefault);
        self::assertSame(5000, $factor->lastUsedAt?->getTimestamp());
        self::assertCount(1, $events->ofType(MfaEnrolled::class));
    }

    public function testSecondFactorConfirmationIssuesNoCodesOrEvent(): void
    {
        $factor = $this->factor();
        $confirmed = $this->factor(id: 'factor-0');
        $confirmed->confirmedAt = new DateTimeImmutable('@100');
        $events = new RecordingEventDispatcher();

        $result = $this->service($factor, matched: 5000, others: [$confirmed, $factor], events: $events)
            ->confirm('user-1', 'factor-1', '123456');

        self::assertSame([], $result->recoveryCodes);
        self::assertNotNull($factor->confirmedAt);
        self::assertCount(0, $events->ofType(MfaEnrolled::class));
    }

    private function factor(
        string $id = 'factor-1',
        string $userId = 'user-1',
        string $type = MfaFactor::TYPE_TOTP,
    ): MfaFactor {
        $now = new DateTimeImmutable('2026-06-08 12:00:00');
        $factor = new MfaFactor();
        $factor->id = $id;
        $factor->userId = $userId;
        $factor->type = $type;
        $factor->secretEncrypted = 'encrypted-secret';
        $factor->createdAt = $now;
        $factor->updatedAt = $now;

        return $factor;
    }

    /**
     * @param list<MfaFactor> $others factors returned by findBy(userId) for the first-confirmation check
     */
    private function service(
        ?MfaFactor $found,
        ?int $matched = 5000,
        array $others = [],
        ?EncrypterInterface $encrypter = null,
        ?RecordingEventDispatcher $events = null,
    ): MfaTotpService {
        $clock = FrozenClock::at('2026-06-08 12:00:00');

        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('find')->willReturn($found);
        $factors->method('findBy')->willReturn($others);

        $totp = $this->createStub(TotpProviderInterface::class);
        $totp->method('matchingTimestamp')->willReturn($matched);

        if ($encrypter === null) {
            $encrypter = $this->createStub(EncrypterInterface::class);
            $encrypter->method('decrypt')->willReturn('SECRET');
        }

        $unitOfWork = new RecordingUnitOfWork();
        $confirmation = new MfaConfirmation(
            $factors,
            new RecoveryCodeService(
                new InMemoryRecoveryCodeRepository($unitOfWork),
                $unitOfWork,
                new Pepper('app-key'),
                $clock,
                new RecordingEventDispatcher(),
            ),
            $unitOfWork,
            $clock,
            $events ?? new RecordingEventDispatcher(),
        );

        return new MfaTotpService(
            $factors,
            $totp,
            $encrypter,
            $this->createStub(QrCodeRendererInterface::class),
            $confirmation,
            $unitOfWork,
            $clock,
        );
    }
}
