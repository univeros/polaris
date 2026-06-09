<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Event\MfaFactorRemoved;
use Univeros\Polaris\Exception\InvalidMfaFactorStateException;
use Univeros\Polaris\Exception\LastFactorProtectedException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;

/**
 * Self-service management of a user's MFA factors (spec §8): list them, relabel / re-default them,
 * and remove them.
 *
 * Removal is guarded: a user for whom MFA is {@see MfaEnforcement enforced} cannot delete their last
 * confirmed factor (they must enrol a replacement first). Removing the default factor promotes the
 * next confirmed one so a confirmed user always keeps a default.
 */
final readonly class MfaManagementService
{
    /**
     * @param RepositoryInterface<MfaFactor> $factors
     */
    public function __construct(
        private RepositoryInterface $factors,
        private MfaEnforcement $enforcement,
        private UnitOfWorkInterface $unitOfWork,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * Every factor the user holds, confirmed or still pending.
     *
     * @return list<MfaFactor>
     */
    public function list(string $userId): array
    {
        $factors = [];
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            $factors[] = $factor;
        }

        return $factors;
    }

    /**
     * Relabel a factor and/or make it the default. A `null` label leaves the label unchanged; an
     * empty-string label clears it. Only a confirmed factor may become the default.
     *
     * @throws MfaFactorNotFoundException        the factor is unknown or another user's
     * @throws InvalidMfaFactorStateException    making an unconfirmed factor the default
     */
    public function update(string $userId, string $factorId, ?string $label, bool $makeDefault): MfaFactor
    {
        $factor = $this->requireOwnedFactor($userId, $factorId);
        $now = $this->clock->now();

        if ($label !== null) {
            $factor->label = $label === '' ? null : $label;
        }

        if ($makeDefault) {
            if ($factor->confirmedAt === null) {
                throw new InvalidMfaFactorStateException('Only a confirmed factor can be the default.');
            }
            $this->clearDefaultExcept($userId, $factorId, $now);
            $factor->isDefault = true;
        }

        $factor->updatedAt = $now;
        $this->unitOfWork->persist($factor);
        $this->unitOfWork->flush();

        return $factor;
    }

    /**
     * Remove a factor. Blocked when it is the user's last confirmed factor and MFA is enforced.
     * Removing the default promotes the next confirmed factor so a confirmed user keeps a default.
     *
     * @throws MfaFactorNotFoundException    the factor is unknown or another user's
     * @throws LastFactorProtectedException  it is the last confirmed factor and MFA is enforced
     */
    public function remove(string $userId, string $factorId): void
    {
        $factor = $this->requireOwnedFactor($userId, $factorId);
        $now = $this->clock->now();

        if (
            $factor->confirmedAt !== null
            && $this->isLastConfirmed($userId, $factorId)
            && $this->enforcement->isEnforced($userId)
        ) {
            throw new LastFactorProtectedException('Enrol another factor before removing your last one.');
        }

        $this->unitOfWork->remove($factor);
        if ($factor->isDefault) {
            $this->promoteNewDefault($userId, $factorId, $now);
        }
        $this->unitOfWork->flush();

        $this->events->dispatch(new MfaFactorRemoved($userId, $factorId));
    }

    /**
     * @throws MfaFactorNotFoundException
     */
    private function requireOwnedFactor(string $userId, string $factorId): MfaFactor
    {
        $factor = $this->factors->find($factorId);
        if (!$factor instanceof MfaFactor || $factor->userId !== $userId) {
            throw new MfaFactorNotFoundException('MFA factor not found.');
        }

        return $factor;
    }

    private function isLastConfirmed(string $userId, string $exceptFactorId): bool
    {
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->id !== $exceptFactorId && $factor->confirmedAt !== null) {
                return false;
            }
        }

        return true;
    }

    private function clearDefaultExcept(string $userId, string $keepFactorId, DateTimeImmutable $now): void
    {
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->id !== $keepFactorId && $factor->isDefault) {
                $factor->isDefault = false;
                $factor->updatedAt = $now;
                $this->unitOfWork->persist($factor);
            }
        }
    }

    private function promoteNewDefault(string $userId, string $removedFactorId, DateTimeImmutable $now): void
    {
        $candidate = null;
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->id === $removedFactorId || $factor->confirmedAt === null) {
                continue;
            }
            if ($candidate === null || $factor->createdAt < $candidate->createdAt) {
                $candidate = $factor;
            }
        }

        if ($candidate !== null) {
            $candidate->isDefault = true;
            $candidate->updatedAt = $now;
            $this->unitOfWork->persist($candidate);
        }
    }
}
