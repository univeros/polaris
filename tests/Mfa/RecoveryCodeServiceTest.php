<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\RecoveryCode;
use Univeros\Polaris\Event\MfaRecoveryRegenerated;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;

use function array_unique;
use function array_values;
use function preg_match;

final class RecoveryCodeServiceTest extends TestCase
{
    public function testIssuesTenUniqueFormattedCodes(): void
    {
        $codes = $this->service()->issue('user-123');

        self::assertCount(RecoveryCodeService::COUNT, $codes);
        self::assertSame($codes, array_values(array_unique($codes)), 'codes are unique');
        foreach ($codes as $code) {
            self::assertSame(1, preg_match('/^[a-z2-7]{5}-[a-z2-7]{5}$/', $code), "well-formed code: $code");
        }
    }

    public function testStoresCodesAsHashesNotPlaintext(): void
    {
        $unitOfWork = new RecordingUnitOfWork();
        $pepper = new Pepper('app-key-for-tests');

        $codes = $this->service($unitOfWork, $pepper)->issue('user-123');

        self::assertSame(0, $unitOfWork->flushes, 'issue() leaves the flush to its caller');
        self::assertCount(RecoveryCodeService::COUNT, $unitOfWork->persisted);
        foreach ($unitOfWork->persisted as $index => $entity) {
            self::assertInstanceOf(RecoveryCode::class, $entity);
            self::assertSame('user-123', $entity->userId);
            self::assertNotSame($codes[$index], $entity->codeHash, 'plaintext is never stored');
            self::assertSame($pepper->hash('recovery', $codes[$index]), $entity->codeHash);
        }
    }

    public function testVerifyAcceptsAValidCodeAndConsumesIt(): void
    {
        $unitOfWork = new RecordingUnitOfWork();
        $service = $this->service($unitOfWork);
        $codes = $service->issue('user-123');

        self::assertTrue($service->verify('user-123', $codes[3]));

        self::assertSame(1, $unitOfWork->flushes, 'a successful verify commits its single stamp');
        $consumed = $unitOfWork->persisted[3];
        self::assertInstanceOf(RecoveryCode::class, $consumed);
        self::assertNotNull($consumed->usedAt, 'a verified code is stamped used');
        self::assertSame(RecoveryCodeService::COUNT - 1, $service->remaining('user-123'));
    }

    public function testVerifyRejectsAnUnknownCode(): void
    {
        $unitOfWork = new RecordingUnitOfWork();
        $service = $this->service($unitOfWork);
        $service->issue('user-123');

        self::assertFalse($service->verify('user-123', 'aaaaa-bbbbb'));
        self::assertSame(0, $unitOfWork->flushes, 'a failed verify writes nothing');
        foreach ($unitOfWork->persisted as $entity) {
            self::assertInstanceOf(RecoveryCode::class, $entity);
            self::assertNull($entity->usedAt, 'a failed verify consumes nothing');
        }
    }

    public function testVerifyIsSingleUse(): void
    {
        $service = $this->service();
        $codes = $service->issue('user-123');

        self::assertTrue($service->verify('user-123', $codes[0]));
        self::assertFalse($service->verify('user-123', $codes[0]), 'a code cannot be reused');
    }

    public function testVerifyDoesNotMatchAnotherUsersCode(): void
    {
        $service = $this->service();
        $codes = $service->issue('user-123');
        $service->issue('user-456');

        self::assertFalse($service->verify('user-456', $codes[0]), 'codes are scoped to their owner');
        self::assertTrue($service->verify('user-123', $codes[0]));
    }

    public function testRegenerateInvalidatesThePriorBatchAndIssuesAFreshOne(): void
    {
        $unitOfWork = new RecordingUnitOfWork();
        $events = new RecordingEventDispatcher();
        $service = $this->service($unitOfWork, events: $events);
        $old = $service->issue('user-123');

        $fresh = $service->regenerate('user-123');

        self::assertSame(1, $unitOfWork->flushes, 'regenerate retires + reissues in a single commit');
        self::assertCount(RecoveryCodeService::COUNT, $fresh);
        self::assertSame(RecoveryCodeService::COUNT, $service->remaining('user-123'), 'only the fresh batch remains usable');
        self::assertFalse($service->verify('user-123', $old[0]), 'a code from the prior batch no longer works');
        self::assertTrue($service->verify('user-123', $fresh[0]), 'a code from the fresh batch works');
        self::assertCount(1, $events->ofType(MfaRecoveryRegenerated::class));
    }

    public function testRemainingCountsOnlyUnusedCodes(): void
    {
        $service = $this->service();
        $codes = $service->issue('user-123');

        self::assertSame(RecoveryCodeService::COUNT, $service->remaining('user-123'));

        $service->verify('user-123', $codes[0]);
        $service->verify('user-123', $codes[1]);

        self::assertSame(RecoveryCodeService::COUNT - 2, $service->remaining('user-123'));
    }

    private function service(
        ?RecordingUnitOfWork $unitOfWork = null,
        ?Pepper $pepper = null,
        ?RecordingEventDispatcher $events = null,
    ): RecoveryCodeService {
        $unitOfWork ??= new RecordingUnitOfWork();

        return new RecoveryCodeService(
            new InMemoryRecoveryCodeRepository($unitOfWork),
            $unitOfWork,
            $pepper ?? new Pepper('app-key-for-tests'),
            FrozenClock::at('2026-06-08 12:00:00'),
            $events ?? new RecordingEventDispatcher(),
        );
    }
}
