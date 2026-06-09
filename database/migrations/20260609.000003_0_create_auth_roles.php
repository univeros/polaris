<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_roles` table behind {@see \Univeros\Polaris\Entity\Role}.
 *
 * `unique(organization_id, slug)` keeps role slugs unique within an organization; a null
 * `organization_id` marks a system/global role. Driver-agnostic: only Cycle's abstract column
 * types are used, so the same migration applies cleanly on every supported database engine.
 */
final class M20260609000003CreateAuthRoles extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_roles')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('organization_id', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('name', 'string', ['size' => 80, 'nullable' => false])
            ->addColumn('slug', 'string', ['size' => 80, 'nullable' => false])
            ->addColumn('description', 'string', ['size' => 255, 'nullable' => true])
            ->addColumn('is_system', 'boolean', ['nullable' => false, 'default' => false])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->addColumn('updated_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['organization_id', 'slug'], ['name' => 'auth_roles_org_slug_unique', 'unique' => true])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_roles')->drop();
    }
}
