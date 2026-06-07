<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Override;
use Univeros\Polaris\Entity\RefreshToken;

use function array_filter;
use function array_key_exists;
use function array_values;
use function get_object_vars;

/**
 * In-memory {@see RefreshToken} store that doubles as both the repository and the unit
 * of work, sharing one identity map keyed by id. Because entities are stored by
 * reference, the in-place mutations {@see \Univeros\Polaris\Token\TokenService} makes
 * (revoking, rotating) are visible to later lookups — matching real ORM behaviour
 * without a database.
 *
 * @implements RepositoryInterface<RefreshToken>
 */
final class InMemoryRefreshTokenRepository implements RepositoryInterface, UnitOfWorkInterface
{
    /** @var array<string, RefreshToken> */
    private array $tokens = [];

    #[Override]
    public function find(int|string $id): ?RefreshToken
    {
        return $this->tokens[(string) $id] ?? null;
    }

    /**
     * @param array<string, mixed> $criteria
     */
    #[Override]
    public function findOneBy(array $criteria): ?RefreshToken
    {
        foreach ($this->tokens as $token) {
            if ($this->matches($token, $criteria)) {
                return $token;
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return list<RefreshToken>
     */
    #[Override]
    public function findBy(array $criteria): iterable
    {
        return array_values(array_filter(
            $this->tokens,
            fn(RefreshToken $token): bool => $this->matches($token, $criteria),
        ));
    }

    /**
     * @return list<RefreshToken>
     */
    #[Override]
    public function findAll(): iterable
    {
        return array_values($this->tokens);
    }

    #[Override]
    public function save(object $entity): void
    {
        $this->persist($entity);
    }

    #[Override]
    public function delete(object $entity): void
    {
        $this->remove($entity);
    }

    #[Override]
    public function persist(object $entity): void
    {
        $this->tokens[$entity->id] = $entity;
    }

    #[Override]
    public function remove(object $entity): void
    {
        unset($this->tokens[$entity->id]);
    }

    #[Override]
    public function flush(): void
    {
        // No-op: persist() commits immediately to the in-memory map.
    }

    #[Override]
    public function clear(): void
    {
        // No-op: entities are held by reference; nothing to detach.
    }

    /**
     * @param array<string, mixed> $criteria
     */
    private function matches(RefreshToken $token, array $criteria): bool
    {
        $fields = get_object_vars($token);

        foreach ($criteria as $field => $value) {
            if (!array_key_exists($field, $fields) || $fields[$field] !== $value) {
                return false;
            }
        }

        return true;
    }
}
