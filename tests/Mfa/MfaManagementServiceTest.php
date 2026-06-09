<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\MfaFactorRemoved;
use Univeros\Polaris\Exception\InvalidMfaFactorStateException;
use Univeros\Polaris\Exception\LastFactorProtectedException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaEnforcement;
use Univeros\Polaris\Mfa\MfaManagementService;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;

final class MfaManagementServiceTest extends TestCase
{
    private const string AT = '2026-06-09 12:00:00';

    private RecordingUnitOfWork $unitOfWork;
    private RecordingEventDispatcher $events;

    public function testListReturnsAllFactors(): void
    {
        $factors = [$this->factor('a'), $this->factor('b', confirmed: false)];

        self::assertSame($factors, $this->service($factors)->list('user-1'));
    }

    public function testUpdateRelabels(): void
    {
        $factor = $this->factor('a');

        $result = $this->service([$factor], find: $factor)->update('user-1', 'a', 'Work phone', false);

        self::assertSame('Work phone', $result->label);
        self::assertContains($factor, $this->unitOfWork->persisted);
    }

    public function testUpdateMakesDefaultAndUnsetsThePrevious(): void
    {
        $previous = $this->factor('a', default: true);
        $target = $this->factor('b');

        $this->service([$previous, $target], find: $target)->update('user-1', 'b', null, true);

        self::assertTrue($target->isDefault);
        self::assertFalse($previous->isDefault, 'the previous default is cleared');
    }

    public function testCannotDefaultAnUnconfirmedFactor(): void
    {
        $factor = $this->factor('a', confirmed: false);

        $this->expectException(InvalidMfaFactorStateException::class);
        $this->service([$factor], find: $factor)->update('user-1', 'a', null, true);
    }

    public function testUpdateRejectsAForeignFactor(): void
    {
        $this->expectException(MfaFactorNotFoundException::class);
        $this->service([], find: null)->update('user-1', 'missing', 'x', false);
    }

    public function testRemoveDeletesAndEmits(): void
    {
        $a = $this->factor('a');
        $b = $this->factor('b');

        $this->service([$a, $b], find: $a)->remove('user-1', 'a');

        self::assertContains($a, $this->unitOfWork->removed);
        self::assertCount(1, $this->events->ofType(MfaFactorRemoved::class));
    }

    public function testRemovingTheLastConfirmedFactorIsBlockedWhenEnforced(): void
    {
        $only = $this->factor('a');

        $this->expectException(LastFactorProtectedException::class);
        $this->service([$only], find: $only, enforced: true)->remove('user-1', 'a');
    }

    public function testRemovingTheLastFactorIsAllowedWhenNotEnforced(): void
    {
        $only = $this->factor('a');

        $this->service([$only], find: $only, enforced: false)->remove('user-1', 'a');

        self::assertContains($only, $this->unitOfWork->removed);
    }

    public function testRemovingADefaultPromotesAnotherConfirmedFactor(): void
    {
        $default = $this->factor('a', default: true);
        $other = $this->factor('b', createdAt: '2026-06-01 09:00:00');

        $this->service([$default, $other], find: $default)->remove('user-1', 'a');

        self::assertTrue($other->isDefault, 'the remaining confirmed factor becomes default');
    }

    /**
     * @param list<MfaFactor> $all
     */
    private function service(array $all, ?MfaFactor $find = null, bool $enforced = false): MfaManagementService
    {
        $this->unitOfWork = new RecordingUnitOfWork();
        $this->events = new RecordingEventDispatcher();

        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('find')->willReturn($find);
        $factors->method('findBy')->willReturn($all);

        $users = $this->createStub(RepositoryInterface::class);
        $user = new User();
        $user->id = 'user-1';
        $user->mfaEnforced = $enforced;
        $users->method('find')->willReturn($user);

        return new MfaManagementService(
            $factors,
            new MfaEnforcement($users, AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test'])),
            $this->unitOfWork,
            FrozenClock::at(self::AT),
            $this->events,
        );
    }

    private function factor(
        string $id,
        bool $confirmed = true,
        bool $default = false,
        string $createdAt = self::AT,
    ): MfaFactor {
        $factor = new MfaFactor();
        $factor->id = $id;
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_TOTP;
        $factor->isDefault = $default;
        $factor->confirmedAt = $confirmed ? new DateTimeImmutable(self::AT) : null;
        $factor->createdAt = new DateTimeImmutable($createdAt);
        $factor->updatedAt = new DateTimeImmutable(self::AT);

        return $factor;
    }
}
