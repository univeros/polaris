<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use DateTimeImmutable;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\PermissionCatalogSeeder;

use function array_column;
use function count;
use function is_array;
use function is_string;

/**
 * Verifies the #30 seed migration against a real database driver: the code-defined
 * {@see PermissionCatalog} drives `auth_permissions`, the four system role templates and their
 * grants are seeded, re-running the seed is idempotent (no duplicates), and the migration rolls
 * back cleanly. The base {@see DatabaseTestCase} has already run the seed migration in setUp.
 */
final class PermissionCatalogSeedPersistenceTest extends DatabaseTestCase
{
    public function testCatalogDrivesAuthPermissions(): void
    {
        $catalog = new PermissionCatalog();
        $expected = $catalog->permissions();

        $rows = $this->connection()->select('key')->from('auth_permissions')->fetchAll();
        $keys = array_column($rows, 'key');

        self::assertCount(count($expected), $keys);
        foreach ($expected as $key => $description) {
            self::assertContains($key, $keys, "auth_permissions should contain seeded key $key");
        }
    }

    public function testSeedsSystemRoleTemplatesWithGrants(): void
    {
        $database = $this->connection();

        self::assertSame(4, $database->select()->from('auth_roles')->where('is_system', true)->count());

        // owner = all 10 org permissions; admin = 9 (no org.delete); member = 3; superadmin = all 12.
        self::assertSame(10, $database->select()->from('auth_role_permissions')->where('role_id', $this->systemRoleId('owner'))->count());
        self::assertSame(9, $database->select()->from('auth_role_permissions')->where('role_id', $this->systemRoleId('admin'))->count());
        self::assertSame(3, $database->select()->from('auth_role_permissions')->where('role_id', $this->systemRoleId('member'))->count());
        self::assertSame(12, $database->select()->from('auth_role_permissions')->where('role_id', $this->systemRoleId('superadmin'))->count());
    }

    public function testReseedingIsIdempotent(): void
    {
        $database = $this->connection();
        $permissionsBefore = $database->select()->from('auth_permissions')->count();
        $rolesBefore = $database->select()->from('auth_roles')->count();
        $grantsBefore = $database->select()->from('auth_role_permissions')->count();

        (new PermissionCatalogSeeder(new PermissionCatalog()))->seed($database, new DateTimeImmutable('2026-06-09 12:00:00'));

        self::assertSame($permissionsBefore, $database->select()->from('auth_permissions')->count());
        self::assertSame($rolesBefore, $database->select()->from('auth_roles')->count());
        self::assertSame($grantsBefore, $database->select()->from('auth_role_permissions')->count());
    }

    public function testMigrationRollsBackCleanly(): void
    {
        while ($this->migrator->rollback() !== null) {
            // Roll back every applied migration, seed first then schema.
        }

        self::assertFalse($this->connection()->hasTable('auth_permissions'));
        self::assertFalse($this->connection()->hasTable('auth_roles'));
    }

    private function systemRoleId(string $slug): string
    {
        foreach ($this->connection()->select(['id', 'organization_id'])->from('auth_roles')->where('slug', $slug)->fetchAll() as $row) {
            if (is_array($row) && is_string($id = $row['id'] ?? null) && ($row['organization_id'] ?? null) === null) {
                return $id;
            }
        }

        self::fail("System role $slug was not seeded");
    }
}
