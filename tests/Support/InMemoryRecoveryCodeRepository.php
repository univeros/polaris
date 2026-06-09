<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Persistence\Contracts\RepositoryInterface;
use LogicException;
use Override;
use Univeros\Polaris\Entity\RecoveryCode;

use function array_key_exists;

/**
 * An in-memory {@see RepositoryInterface} over {@see RecoveryCode} rows that reads straight from a
 * {@see RecordingUnitOfWork}'s persisted set, so a service can `issue()` then `verify()`/`regenerate()`
 * within a single instance — exactly as it would against a real repository sharing the unit of work.
 *
 * @implements RepositoryInterface<RecoveryCode>
 */
final readonly class InMemoryRecoveryCodeRepository implements RepositoryInterface
{
    public function __construct(private RecordingUnitOfWork $unitOfWork)
    {
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return list<RecoveryCode>
     */
    #[Override]
    public function findBy(array $criteria): iterable
    {
        $matches = [];
        foreach ($this->unitOfWork->persisted as $entity) {
            if (!$entity instanceof RecoveryCode) {
                continue;
            }
            if (isset($criteria['userId']) && $entity->userId !== $criteria['userId']) {
                continue;
            }
            if (isset($criteria['id']) && $entity->id !== $criteria['id']) {
                continue;
            }
            // array_key_exists, not isset: the `usedAt => null` scope (Cycle's `used_at IS NULL`) is
            // the common case and isset() is false for a null value.
            if (array_key_exists('usedAt', $criteria) && $entity->usedAt !== $criteria['usedAt']) {
                continue;
            }
            $matches[] = $entity;
        }

        return $matches;
    }

    /**
     * @param array<string, mixed> $criteria
     */
    #[Override]
    public function findOneBy(array $criteria): ?object
    {
        return $this->findBy($criteria)[0] ?? null;
    }

    #[Override]
    public function find(int|string $id): ?object
    {
        return $this->findOneBy(['id' => $id]);
    }

    /**
     * @return list<RecoveryCode>
     */
    #[Override]
    public function findAll(): iterable
    {
        return $this->findBy([]);
    }

    #[Override]
    public function save(object $entity): void
    {
        throw new LogicException('InMemoryRecoveryCodeRepository is read-only; persist via the unit of work.');
    }

    #[Override]
    public function delete(object $entity): void
    {
        throw new LogicException('InMemoryRecoveryCodeRepository does not delete.');
    }
}
