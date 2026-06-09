<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_memberships` table behind {@see \Univeros\Polaris\Entity\Membership}.
 *
 * The `unique(user_id, organization_id)` index enforces one membership per user per organization.
 * Driver-agnostic: only Cycle's abstract column types are used, so the same migration applies
 * cleanly on every supported database engine.
 */
final class M20260609000002CreateAuthMemberships extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_memberships')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('user_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('organization_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('status', 'string', ['size' => 16, 'nullable' => false, 'default' => 'invited'])
            ->addColumn('invited_by', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('joined_at', 'datetime', ['nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->addColumn('updated_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['user_id', 'organization_id'], ['name' => 'auth_memberships_user_org_unique', 'unique' => true])
            ->addIndex(['organization_id', 'status'], ['name' => 'auth_memberships_org_status_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_memberships')->drop();
    }
}
