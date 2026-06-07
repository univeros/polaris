<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Http\Validator\RepositoryIdentityValidator;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Argon2idPasswordHasher;

/**
 * End-to-end credential check against a real database driver: a persisted user is
 * looked up through {@see UserRepository} + {@see CycleIdentityProvider} and verified
 * by the framework's {@see RepositoryIdentityValidator} — the same chain the module
 * wires at runtime (issue #8).
 */
final class CredentialValidatorPersistenceTest extends DatabaseTestCase
{
    private const string PASSWORD = 's3cret-password-123';

    public function testAuthenticatesAPersistedUser(): void
    {
        $validator = $this->validatorWithPersistedUser('grace@example.com');

        self::assertTrue($validator(['user' => 'grace@example.com', 'password' => self::PASSWORD]));
    }

    public function testRejectsAWrongPasswordForAPersistedUser(): void
    {
        $validator = $this->validatorWithPersistedUser('grace@example.com');

        self::assertFalse($validator(['user' => 'grace@example.com', 'password' => 'not-the-password']));
    }

    public function testRejectsAnUnknownUser(): void
    {
        $validator = $this->validatorWithPersistedUser('grace@example.com');

        self::assertFalse($validator(['user' => 'ghost@example.com', 'password' => self::PASSWORD]));
    }

    public function testProviderReturnsTheColumnKeyedRecord(): void
    {
        $this->validatorWithPersistedUser('grace@example.com');
        $provider = new CycleIdentityProvider(new UserRepository($this->orm, $this->unitOfWork));

        $record = $provider->findOneBy(['email' => 'grace@example.com']);

        self::assertIsArray($record);
        self::assertSame('grace@example.com', $record['email']);
        self::assertArrayHasKey(CycleIdentityProvider::PASSWORD_HASH_FIELD, $record);
    }

    private function validatorWithPersistedUser(string $email): RepositoryIdentityValidator
    {
        // Low cost keeps the suite fast; production uses the documented defaults.
        $hasher = new Argon2idPasswordHasher(['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]);
        $now = new DateTimeImmutable('2026-06-07 10:00:00');

        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->passwordHash = $hasher->hash(self::PASSWORD);
        $user->createdAt = $now;
        $user->updatedAt = $now;

        $repository = new UserRepository($this->orm, $this->unitOfWork);
        $repository->save($user);
        $this->unitOfWork->clear();

        $provider = new CycleIdentityProvider(new UserRepository($this->orm, $this->unitOfWork));

        return new RepositoryIdentityValidator($provider, [
            'username' => CycleIdentityProvider::IDENTIFIER_FIELD,
            'hash' => CycleIdentityProvider::PASSWORD_HASH_FIELD,
        ]);
    }
}
