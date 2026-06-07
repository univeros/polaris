<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\EmailVerification;
use Univeros\Polaris\Entity\PasswordReset;

use function str_repeat;

/**
 * Verifies the #6 transient single-use token entities and migrations against a real
 * database driver: the migrations create the hashed-token + expiry schema, the
 * attribute-mapped entities round-trip through it, and the migrations roll back
 * cleanly.
 */
final class TransientTokenEntitiesPersistenceTest extends DatabaseTestCase
{
    public function testMigrationsCreateTransientTokenTables(): void
    {
        $database = $this->connection();

        self::assertTrue($database->hasTable('auth_email_verifications'));
        self::assertTrue($database->hasTable('auth_password_resets'));

        foreach (['auth_email_verifications', 'auth_password_resets'] as $name) {
            $table = $database->table($name);
            foreach (['id', 'user_id', 'email', 'token_hash', 'expires_at', 'consumed_at', 'ip', 'created_at'] as $column) {
                self::assertTrue($table->hasColumn($column), "$name.$column should exist");
            }
        }
    }

    public function testEmailVerificationRoundTrips(): void
    {
        $repository = new CycleRepository(EmailVerification::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-07 10:00:00');
        $hash = str_repeat('a', 64);

        $verification = new EmailVerification();
        $verification->id = Uuid::v7()->toRfc4122();
        $verification->userId = Uuid::v7()->toRfc4122();
        $verification->email = 'ada@example.com';
        $verification->tokenHash = $hash;
        $verification->expiresAt = $now->modify('+24 hours');
        $verification->ip = '203.0.113.7';
        $verification->createdAt = $now;
        $repository->save($verification);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['tokenHash' => $hash]);

        self::assertInstanceOf(EmailVerification::class, $found);
        self::assertSame($verification->id, $found->id);
        self::assertSame($verification->userId, $found->userId);
        self::assertSame('ada@example.com', $found->email);
        self::assertSame($hash, $found->tokenHash);
        self::assertSame('203.0.113.7', $found->ip);
        self::assertNull($found->consumedAt);
        self::assertInstanceOf(DateTimeImmutable::class, $found->expiresAt);
        self::assertInstanceOf(DateTimeImmutable::class, $found->createdAt);
    }

    public function testPasswordResetRoundTripsAndRecordsConsumption(): void
    {
        $repository = new CycleRepository(PasswordReset::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-07 10:00:00');
        $hash = str_repeat('b', 64);

        $reset = new PasswordReset();
        $reset->id = Uuid::v7()->toRfc4122();
        $reset->userId = Uuid::v7()->toRfc4122();
        $reset->email = 'grace@example.com';
        $reset->tokenHash = $hash;
        $reset->expiresAt = $now->modify('+1 hour');
        $reset->consumedAt = $now->modify('+5 minutes');
        $reset->createdAt = $now;
        $repository->save($reset);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['tokenHash' => $hash]);

        self::assertInstanceOf(PasswordReset::class, $found);
        self::assertSame($reset->id, $found->id);
        self::assertSame('grace@example.com', $found->email);
        self::assertNull($found->ip);
        self::assertInstanceOf(DateTimeImmutable::class, $found->consumedAt);
    }

    public function testMigrationsRollBackCleanly(): void
    {
        while ($this->migrator->rollback() !== null) {
            // Roll back every applied migration.
        }

        $database = $this->connection();

        self::assertFalse($database->hasTable('auth_email_verifications'));
        self::assertFalse($database->hasTable('auth_password_resets'));
    }
}
