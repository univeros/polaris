<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Entity\User;

use function str_repeat;

/**
 * Verifies the #5 entities and migrations against a real database driver:
 * the migrations create the expected portable schema, the attribute-mapped
 * entities round-trip through it, and the migrations roll back cleanly.
 */
final class AuthEntitiesPersistenceTest extends DatabaseTestCase
{
    public function testMigrationsCreateAuthTables(): void
    {
        $database = $this->connection();

        self::assertTrue($database->hasTable('auth_users'));
        self::assertTrue($database->hasTable('auth_refresh_tokens'));

        $users = $database->table('auth_users');
        foreach (['id', 'email', 'password_hash', 'status', 'mfa_enforced', 'failed_login_at', 'created_at'] as $column) {
            self::assertTrue($users->hasColumn($column), "auth_users.$column should exist");
        }

        $tokens = $database->table('auth_refresh_tokens');
        foreach (['id', 'user_id', 'family_id', 'token_hash', 'expires_at', 'revoked_at'] as $column) {
            self::assertTrue($tokens->hasColumn($column), "auth_refresh_tokens.$column should exist");
        }
    }

    public function testUserRoundTrips(): void
    {
        $repository = new CycleRepository(User::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-07 10:00:00');

        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->displayName = 'Ada';
        $user->failedLoginCount = 2;
        $user->failedLoginAt = $now;
        $user->createdAt = $now;
        $user->updatedAt = $now;
        $repository->save($user);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['email' => 'ada@example.com']);

        self::assertInstanceOf(User::class, $found);
        self::assertSame($user->id, $found->id);
        self::assertSame('ada@example.com', $found->email);
        self::assertSame('Ada', $found->displayName);
        self::assertSame('active', $found->status);
        self::assertFalse($found->mfaEnforced);
        self::assertSame(2, $found->failedLoginCount);
        self::assertInstanceOf(DateTimeImmutable::class, $found->failedLoginAt);
        self::assertNull($found->emailVerifiedAt);
        self::assertNull($found->passwordHash);
        self::assertInstanceOf(DateTimeImmutable::class, $found->createdAt);
    }

    public function testRefreshTokenRoundTrips(): void
    {
        $repository = new CycleRepository(RefreshToken::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-07 10:00:00');
        $hash = str_repeat('a', 64);

        $token = new RefreshToken();
        $token->id = Uuid::v7()->toRfc4122();
        $token->userId = Uuid::v7()->toRfc4122();
        $token->familyId = Uuid::v7()->toRfc4122();
        $token->tokenHash = $hash;
        $token->expiresAt = $now->modify('+30 days');
        $token->createdAt = $now;
        $repository->save($token);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['tokenHash' => $hash]);

        self::assertInstanceOf(RefreshToken::class, $found);
        self::assertSame($token->id, $found->id);
        self::assertSame($token->userId, $found->userId);
        self::assertSame($token->familyId, $found->familyId);
        self::assertNull($found->organizationId);
        self::assertNull($found->parentId);
        self::assertNull($found->revokedAt);
        self::assertNull($found->revokedReason);
        self::assertInstanceOf(DateTimeImmutable::class, $found->expiresAt);
    }

    public function testMigrationsRollBackCleanly(): void
    {
        while ($this->migrator->rollback() !== null) {
            // Roll back every applied migration.
        }

        $database = $this->connection();

        self::assertFalse($database->hasTable('auth_users'));
        self::assertFalse($database->hasTable('auth_refresh_tokens'));
    }
}
