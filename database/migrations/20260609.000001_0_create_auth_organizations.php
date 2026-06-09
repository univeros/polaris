<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_organizations` table behind {@see \Univeros\Polaris\Entity\Organization}.
 *
 * Driver-agnostic: only Cycle's abstract column types are used, so the same migration applies
 * cleanly on every supported database engine.
 */
final class M20260609000001CreateAuthOrganizations extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_organizations')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('name', 'string', ['size' => 160, 'nullable' => false])
            ->addColumn('slug', 'string', ['size' => 160, 'nullable' => false])
            ->addColumn('status', 'string', ['size' => 16, 'nullable' => false, 'default' => 'active'])
            ->addColumn('created_by', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->addColumn('updated_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['slug'], ['name' => 'auth_organizations_slug_unique', 'unique' => true])
            ->addIndex(['status'], ['name' => 'auth_organizations_status_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_organizations')->drop();
    }
}
