<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;
use DateTimeImmutable;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\PermissionCatalogSeeder;

use function array_keys;

/**
 * Seeds the permission catalog and the system role templates from the code-defined
 * {@see PermissionCatalog} (the single source of truth).
 *
 * Data migration, not schema: it delegates to {@see PermissionCatalogSeeder}, which is idempotent
 * (every row is looked up before insert), so a partial or repeated run never duplicates. `down()`
 * removes only what was seeded; deleting the system roles cascades their permission grants.
 */
final class M20260609000008SeedPermissionsAndSystemRoles extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        (new PermissionCatalogSeeder(new PermissionCatalog()))->seed($this->database(), new DateTimeImmutable('now'));
    }

    public function down(): void
    {
        $database = $this->database();
        $catalog = new PermissionCatalog();

        // Dropping the system roles cascades their auth_role_permissions rows.
        foreach ($catalog->roleTemplates() as $template) {
            $database->delete('auth_roles', ['slug' => $template->slug, 'is_system' => true])->run();
        }

        foreach (array_keys($catalog->permissions()) as $key) {
            $database->delete('auth_permissions', ['key' => $key])->run();
        }
    }
}
