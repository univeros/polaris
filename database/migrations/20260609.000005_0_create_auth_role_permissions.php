<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_role_permissions` join table behind {@see \Univeros\Polaris\Entity\RolePermission}.
 *
 * Composite primary key `(role_id, permission_id)` makes each grant unique; both columns are
 * `ON DELETE CASCADE` foreign keys, so deleting a role or a permission removes its grants and never
 * leaves an orphaned pairing. Runs after `auth_roles` and `auth_permissions` exist so the foreign
 * keys resolve. Driver-agnostic: only Cycle's abstract column types are used.
 */
final class M20260609000005CreateAuthRolePermissions extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_role_permissions')
            ->addColumn('role_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('permission_id', 'string', ['size' => 36, 'nullable' => false])
            ->setPrimaryKeys(['role_id', 'permission_id'])
            ->addForeignKey(['role_id'], 'auth_roles', ['id'], ['delete' => 'CASCADE', 'update' => 'CASCADE'])
            ->addForeignKey(['permission_id'], 'auth_permissions', ['id'], ['delete' => 'CASCADE', 'update' => 'CASCADE'])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_role_permissions')->drop();
    }
}
