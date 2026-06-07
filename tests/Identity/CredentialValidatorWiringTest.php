<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Identity;

use Altair\Http\Validator\RepositoryIdentityValidator;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Security\Argon2idPasswordHasher;
use Univeros\Polaris\Tests\Support\InMemoryUserRepository;

/**
 * Acceptance test for issue #8: the framework's {@see RepositoryIdentityValidator},
 * wired over {@see CycleIdentityProvider} exactly as {@see \Univeros\Polaris\Module}
 * binds it, authenticates valid credentials and rejects everything else. Proves the
 * Argon2id hashes Polaris produces verify under the framework's native check.
 */
final class CredentialValidatorWiringTest extends TestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    public function testAuthenticatesValidCredentials(): void
    {
        $validator = $this->validator($this->user());

        self::assertTrue($validator(['user' => 'ada@example.com', 'password' => self::PASSWORD]));
    }

    public function testRejectsAWrongPassword(): void
    {
        $validator = $this->validator($this->user());

        self::assertFalse($validator(['user' => 'ada@example.com', 'password' => 'wrong password']));
    }

    public function testRejectsAnUnknownUser(): void
    {
        $validator = $this->validator($this->user());

        self::assertFalse($validator(['user' => 'nobody@example.com', 'password' => self::PASSWORD]));
    }

    public function testRejectsAUserWithoutAPassword(): void
    {
        $user = $this->user();
        $user->passwordHash = null;

        $validator = $this->validator($user);

        self::assertFalse($validator(['user' => 'ada@example.com', 'password' => self::PASSWORD]));
    }

    private function validator(User $user): RepositoryIdentityValidator
    {
        $provider = new CycleIdentityProvider(new InMemoryUserRepository($user));

        return new RepositoryIdentityValidator($provider, [
            'username' => CycleIdentityProvider::IDENTIFIER_FIELD,
            'hash' => CycleIdentityProvider::PASSWORD_HASH_FIELD,
        ]);
    }

    private function user(): User
    {
        // Low cost keeps the suite fast; production uses the documented defaults.
        $hasher = new Argon2idPasswordHasher(['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]);
        $now = new DateTimeImmutable('2026-06-07 10:00:00');

        $user = new User();
        $user->id = '0197f0a0-0000-7000-8000-000000000000';
        $user->email = 'ada@example.com';
        $user->passwordHash = $hasher->hash(self::PASSWORD);
        $user->createdAt = $now;
        $user->updatedAt = $now;

        return $user;
    }
}
