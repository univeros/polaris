<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Identity;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Tests\Support\InMemoryUserRepository;

use function array_keys;

final class CycleIdentityProviderTest extends TestCase
{
    public function testFindsTheRecordByEmailKeyedByColumnName(): void
    {
        $provider = new CycleIdentityProvider(new InMemoryUserRepository($this->user()));

        $record = $provider->findOneBy([CycleIdentityProvider::IDENTIFIER_FIELD => 'ada@example.com']);

        self::assertIsArray($record);
        self::assertSame('ada@example.com', $record['email']);
        self::assertSame('hashed-secret', $record[CycleIdentityProvider::PASSWORD_HASH_FIELD]);
        self::assertSame('0197f0a0-0000-7000-8000-000000000000', $record['id']);
    }

    public function testExposesOnlyTheCredentialFields(): void
    {
        $provider = new CycleIdentityProvider(new InMemoryUserRepository($this->user()));

        $record = $provider->findOneBy([CycleIdentityProvider::IDENTIFIER_FIELD => 'ada@example.com']);

        self::assertIsArray($record);
        // The hash must not travel alongside profile/policy fields a caller might log.
        self::assertSame(['id', 'email', 'password_hash'], array_keys($record));
    }

    public function testReturnsNullWhenNoUserMatches(): void
    {
        $provider = new CycleIdentityProvider(new InMemoryUserRepository($this->user()));

        self::assertNull($provider->findOneBy([CycleIdentityProvider::IDENTIFIER_FIELD => 'nobody@example.com']));
    }

    public function testReturnsNullForAnEmptyRepository(): void
    {
        $provider = new CycleIdentityProvider(new InMemoryUserRepository());

        self::assertNull($provider->findOneBy([CycleIdentityProvider::IDENTIFIER_FIELD => 'ada@example.com']));
    }

    public function testExposesAPasswordHashKeyEvenWhenTheUserHasNoPassword(): void
    {
        $user = $this->user();
        $user->passwordHash = null;
        $provider = new CycleIdentityProvider(new InMemoryUserRepository($user));

        $record = $provider->findOneBy([CycleIdentityProvider::IDENTIFIER_FIELD => 'ada@example.com']);

        self::assertIsArray($record);
        self::assertArrayHasKey(CycleIdentityProvider::PASSWORD_HASH_FIELD, $record);
        self::assertNull($record[CycleIdentityProvider::PASSWORD_HASH_FIELD]);
    }

    private function user(): User
    {
        $now = new DateTimeImmutable('2026-06-07 10:00:00');

        $user = new User();
        $user->id = '0197f0a0-0000-7000-8000-000000000000';
        $user->email = 'ada@example.com';
        $user->passwordHash = 'hashed-secret';
        $user->displayName = 'Ada';
        $user->createdAt = $now;
        $user->updatedAt = $now;

        return $user;
    }
}
