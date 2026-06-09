<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Cycle\Database\DatabaseInterface;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

use function is_array;
use function is_string;

/**
 * Writes the {@see PermissionCatalog} into the database — permissions, the system role templates,
 * and the grants linking them.
 *
 * Idempotent by design: every row is looked up before insert, so running the seed repeatedly (or
 * after the catalog grows) converges without duplicates and never disturbs existing ids. The seed
 * migration delegates here; a host could also re-run it after registering new permission
 * contributors. The database is the projection; the catalog is the source of truth.
 */
final readonly class PermissionCatalogSeeder
{
    public function __construct(private PermissionCatalog $catalog)
    {
    }

    public function seed(DatabaseInterface $database, DateTimeImmutable $now): void
    {
        $permissionIds = [];
        foreach ($this->catalog->permissions() as $key => $description) {
            $permissionIds[$key] = $this->ensurePermission($database, $key, $description);
        }

        foreach ($this->catalog->roleTemplates() as $template) {
            $roleId = $this->ensureSystemRole($database, $template, $now);
            foreach ($template->permissionKeys as $key) {
                $permissionId = $permissionIds[$key] ?? null;
                if ($permissionId !== null) {
                    $this->ensureRolePermission($database, $roleId, $permissionId);
                }
            }
        }
    }

    private function ensurePermission(DatabaseInterface $database, string $key, string $description): string
    {
        foreach ($database->select('id')->from('auth_permissions')->where('key', $key)->fetchAll() as $row) {
            if (is_array($row) && is_string($id = $row['id'] ?? null)) {
                return $id;
            }
        }

        $id = Uuid::v7()->toRfc4122();
        $database->insert('auth_permissions')
            ->values(['id' => $id, 'key' => $key, 'description' => $description])
            ->run();

        return $id;
    }

    private function ensureSystemRole(DatabaseInterface $database, RoleTemplate $template, DateTimeImmutable $now): string
    {
        // System roles have organization_id IS NULL; match by slug among them.
        foreach ($database->select(['id', 'organization_id'])->from('auth_roles')->where('slug', $template->slug)->fetchAll() as $row) {
            if (is_array($row) && is_string($id = $row['id'] ?? null) && ($row['organization_id'] ?? null) === null) {
                return $id;
            }
        }

        $id = Uuid::v7()->toRfc4122();
        $database->insert('auth_roles')
            ->values([
                'id' => $id,
                'organization_id' => null,
                'name' => $template->name,
                'slug' => $template->slug,
                'description' => $template->description,
                'is_system' => true,
                'created_at' => $now,
                'updated_at' => $now,
            ])
            ->run();

        return $id;
    }

    private function ensureRolePermission(DatabaseInterface $database, string $roleId, string $permissionId): void
    {
        $existing = $database->select('role_id')
            ->from('auth_role_permissions')
            ->where(['role_id' => $roleId, 'permission_id' => $permissionId])
            ->fetchAll();

        if ($existing === []) {
            $database->insert('auth_role_permissions')
                ->values(['role_id' => $roleId, 'permission_id' => $permissionId])
                ->run();
        }
    }
}
