<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Persistence\Contracts\RepositoryInterface;
use Override;
use Univeros\Polaris\Entity\User;

use function array_filter;
use function array_key_exists;
use function array_values;
use function get_object_vars;

/**
 * In-memory {@see RepositoryInterface} over {@see User}, for unit tests that need
 * the identity lookup without a database. Criteria are matched against the User's
 * public properties (the entity field names), mirroring how Cycle resolves them.
 *
 * @implements RepositoryInterface<User>
 */
final class InMemoryUserRepository implements RepositoryInterface
{
    /** @var list<User> */
    private array $users;

    public function __construct(User ...$users)
    {
        $this->users = array_values($users);
    }

    #[Override]
    public function find(int|string $id): ?User
    {
        return $this->findOneBy(['id' => $id]);
    }

    /**
     * @param array<string, mixed> $criteria
     */
    #[Override]
    public function findOneBy(array $criteria): ?User
    {
        foreach ($this->users as $user) {
            if ($this->matches($user, $criteria)) {
                return $user;
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return list<User>
     */
    #[Override]
    public function findBy(array $criteria): iterable
    {
        return array_values(array_filter(
            $this->users,
            fn(User $user): bool => $this->matches($user, $criteria),
        ));
    }

    /**
     * @return list<User>
     */
    #[Override]
    public function findAll(): iterable
    {
        return $this->users;
    }

    #[Override]
    public function save(object $entity): void
    {
        $this->users = array_values(array_filter(
            $this->users,
            static fn(User $user): bool => $user->id !== $entity->id,
        ));
        $this->users[] = $entity;
    }

    #[Override]
    public function delete(object $entity): void
    {
        $this->users = array_values(array_filter(
            $this->users,
            static fn(User $user): bool => $user->id !== $entity->id,
        ));
    }

    /**
     * Match criteria against the User's initialised public properties (the entity
     * field names), comparing by identity so a `null` criterion matches a `null`
     * field — mirroring how Cycle resolves `field => null` as `IS NULL`.
     *
     * @param array<string, mixed> $criteria
     */
    private function matches(User $user, array $criteria): bool
    {
        $fields = get_object_vars($user);

        foreach ($criteria as $field => $value) {
            if (!array_key_exists($field, $fields) || $fields[$field] !== $value) {
                return false;
            }
        }

        return true;
    }
}
