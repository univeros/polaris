<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Univeros\Polaris\Entity\Invitation;

use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Verifies the #29 invitation entity and migration against a real database driver: the migration
 * creates the expected portable table, columns and indexes (including `unique(token_hash)`); the
 * attribute-mapped entity round-trips — including the JSON `role_ids` payload and the expiry — the
 * hashed-token uniqueness is enforced; and the migration rolls back cleanly.
 */
final class InvitationPersistenceTest extends DatabaseTestCase
{
    public function testMigrationCreatesTheTableWithIndexes(): void
    {
        $database = $this->connection();

        self::assertTrue($database->hasTable('auth_invitations'));

        $invitations = $database->table('auth_invitations');
        foreach (['id', 'organization_id', 'email', 'role_ids', 'token_hash', 'invited_by', 'expires_at', 'accepted_at', 'created_at'] as $column) {
            self::assertTrue($invitations->hasColumn($column), "auth_invitations.$column should exist");
        }
        self::assertTrue($invitations->hasIndex(['token_hash']));
        self::assertTrue($invitations->hasIndex(['organization_id']));
        self::assertTrue($invitations->hasIndex(['email']));
    }

    public function testInvitationRoundTrips(): void
    {
        $repository = new CycleRepository(Invitation::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');
        $roleIds = [Uuid::v7()->toRfc4122(), Uuid::v7()->toRfc4122()];
        $tokenHash = Uuid::v7()->toRfc4122();

        $invitation = new Invitation();
        $invitation->id = Uuid::v7()->toRfc4122();
        $invitation->organizationId = Uuid::v7()->toRfc4122();
        $invitation->email = 'invitee@example.com';
        $invitation->roleIds = json_encode($roleIds, JSON_THROW_ON_ERROR);
        $invitation->tokenHash = $tokenHash;
        $invitation->invitedBy = Uuid::v7()->toRfc4122();
        $invitation->expiresAt = $now->modify('+7 days');
        $invitation->createdAt = $now;
        $repository->save($invitation);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['tokenHash' => $tokenHash]);

        self::assertInstanceOf(Invitation::class, $found);
        self::assertSame('invitee@example.com', $found->email);
        self::assertSame($invitation->organizationId, $found->organizationId);
        self::assertSame($invitation->invitedBy, $found->invitedBy);
        self::assertSame($roleIds, json_decode($found->roleIds, true, 512, JSON_THROW_ON_ERROR));
        self::assertNull($found->acceptedAt);
        self::assertInstanceOf(DateTimeImmutable::class, $found->expiresAt);
        self::assertSame('2026-06-16 10:00:00', $found->expiresAt->format('Y-m-d H:i:s'));
    }

    public function testTokenHashIsUnique(): void
    {
        $repository = new CycleRepository(Invitation::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');
        $tokenHash = Uuid::v7()->toRfc4122();

        $first = $this->newInvitation($tokenHash, $now);
        $repository->save($first);

        $this->unitOfWork->clear();

        $violated = false;
        try {
            $repository->save($this->newInvitation($tokenHash, $now));
        } catch (Throwable) {
            $violated = true;
        }

        self::assertTrue($violated, 'Two invitations sharing a token hash must violate the unique index.');
    }

    public function testMigrationsRollBackCleanly(): void
    {
        while ($this->migrator->rollback() !== null) {
            // Roll back every applied migration.
        }

        self::assertFalse($this->connection()->hasTable('auth_invitations'));
    }

    private function newInvitation(string $tokenHash, DateTimeImmutable $now): Invitation
    {
        $invitation = new Invitation();
        $invitation->id = Uuid::v7()->toRfc4122();
        $invitation->organizationId = Uuid::v7()->toRfc4122();
        $invitation->email = 'invitee@example.com';
        $invitation->tokenHash = $tokenHash;
        $invitation->invitedBy = Uuid::v7()->toRfc4122();
        $invitation->expiresAt = $now->modify('+7 days');
        $invitation->createdAt = $now;

        return $invitation;
    }
}
