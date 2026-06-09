<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Cycle\CycleRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\Organization;

/**
 * Verifies the #27 RBAC entities and migrations against a real database driver: the migrations
 * create the expected portable tables, columns, and indexes (including the
 * `unique(user_id, organization_id)` membership constraint); the attribute-mapped entities
 * round-trip through them; the unique constraint is enforced; and the migrations roll back cleanly.
 */
final class OrgMembershipPersistenceTest extends DatabaseTestCase
{
    public function testMigrationsCreateTheTablesWithIndexes(): void
    {
        $database = $this->connection();

        self::assertTrue($database->hasTable('auth_organizations'));
        self::assertTrue($database->hasTable('auth_memberships'));

        $organizations = $database->table('auth_organizations');
        foreach (['id', 'name', 'slug', 'status', 'created_by', 'created_at', 'updated_at'] as $column) {
            self::assertTrue($organizations->hasColumn($column), "auth_organizations.$column should exist");
        }
        self::assertTrue($organizations->hasIndex(['slug']));
        self::assertTrue($organizations->hasIndex(['status']));

        $memberships = $database->table('auth_memberships');
        foreach (['id', 'user_id', 'organization_id', 'status', 'invited_by', 'joined_at'] as $column) {
            self::assertTrue($memberships->hasColumn($column), "auth_memberships.$column should exist");
        }
        self::assertTrue($memberships->hasIndex(['user_id', 'organization_id']));
        self::assertTrue($memberships->hasIndex(['organization_id', 'status']));
    }

    public function testOrganizationRoundTrips(): void
    {
        $repository = new CycleRepository(Organization::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $organization = new Organization();
        $organization->id = Uuid::v7()->toRfc4122();
        $organization->name = 'Acme Inc';
        $organization->slug = 'acme';
        $organization->status = Organization::STATUS_ACTIVE;
        $organization->createdBy = Uuid::v7()->toRfc4122();
        $organization->createdAt = $now;
        $organization->updatedAt = $now;
        $repository->save($organization);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['slug' => 'acme']);

        self::assertInstanceOf(Organization::class, $found);
        self::assertSame('Acme Inc', $found->name);
        self::assertSame(Organization::STATUS_ACTIVE, $found->status);
        self::assertSame($organization->createdBy, $found->createdBy);
    }

    public function testMembershipRoundTrips(): void
    {
        $repository = new CycleRepository(Membership::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = Uuid::v7()->toRfc4122();
        $membership->organizationId = Uuid::v7()->toRfc4122();
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->invitedBy = Uuid::v7()->toRfc4122();
        $membership->joinedAt = $now;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        $repository->save($membership);

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['id' => $membership->id]);

        self::assertInstanceOf(Membership::class, $found);
        self::assertSame($membership->userId, $found->userId);
        self::assertSame($membership->organizationId, $found->organizationId);
        self::assertSame(Membership::STATUS_ACTIVE, $found->status);
        self::assertSame($membership->invitedBy, $found->invitedBy);
        self::assertInstanceOf(DateTimeImmutable::class, $found->joinedAt);
    }

    public function testMembershipUserOrgPairIsUnique(): void
    {
        $repository = new CycleRepository(Membership::class, $this->orm, $this->unitOfWork);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');
        $userId = Uuid::v7()->toRfc4122();
        $organizationId = Uuid::v7()->toRfc4122();

        $first = new Membership();
        $first->id = Uuid::v7()->toRfc4122();
        $first->userId = $userId;
        $first->organizationId = $organizationId;
        $first->createdAt = $now;
        $first->updatedAt = $now;
        $repository->save($first);

        $this->unitOfWork->clear();

        $duplicate = new Membership();
        $duplicate->id = Uuid::v7()->toRfc4122();
        $duplicate->userId = $userId;
        $duplicate->organizationId = $organizationId;
        $duplicate->createdAt = $now;
        $duplicate->updatedAt = $now;

        $violated = false;
        try {
            $repository->save($duplicate);
        } catch (Throwable) {
            $violated = true;
        }

        self::assertTrue($violated, 'A second membership for the same user/org pair must violate the unique index.');
    }

    public function testMigrationsRollBackCleanly(): void
    {
        while ($this->migrator->rollback() !== null) {
            // Roll back every applied migration.
        }

        $database = $this->connection();

        self::assertFalse($database->hasTable('auth_organizations'));
        self::assertFalse($database->hasTable('auth_memberships'));
    }
}
