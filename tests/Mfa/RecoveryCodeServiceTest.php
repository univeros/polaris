<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\RecoveryCode;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;

use function array_unique;
use function array_values;
use function preg_match;

final class RecoveryCodeServiceTest extends TestCase
{
    public function testIssuesTenUniqueFormattedCodes(): void
    {
        $codes = $this->service(new RecordingUnitOfWork())->issue('user-123');

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

        self::assertCount(RecoveryCodeService::COUNT, $unitOfWork->persisted);
        foreach ($unitOfWork->persisted as $index => $entity) {
            self::assertInstanceOf(RecoveryCode::class, $entity);
            self::assertSame('user-123', $entity->userId);
            self::assertNotSame($codes[$index], $entity->codeHash, 'plaintext is never stored');
            self::assertSame($pepper->hash('recovery', $codes[$index]), $entity->codeHash);
        }
    }

    private function service(RecordingUnitOfWork $unitOfWork, ?Pepper $pepper = null): RecoveryCodeService
    {
        return new RecoveryCodeService(
            $unitOfWork,
            $pepper ?? new Pepper('app-key-for-tests'),
            FrozenClock::at('2026-06-08 12:00:00'),
        );
    }
}
