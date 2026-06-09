<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_membership_roles` join table behind {@see \Univeros\Polaris\Entity\MembershipRole}.
 *
 * This binds a user's roles *within a specific organization*. Composite primary key
 * `(membership_id, role_id)` makes each pairing unique; both columns are `ON DELETE CASCADE`
 * foreign keys, so removing a membership or a role drops the grant automatically. Runs after
 * `auth_memberships` and `auth_roles` exist so the foreign keys resolve. Driver-agnostic: only
 * Cycle's abstract column types are used.
 */
final class M20260609000006CreateAuthMembershipRoles extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_membership_roles')
            ->addColumn('membership_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('role_id', 'string', ['size' => 36, 'nullable' => false])
            ->setPrimaryKeys(['membership_id', 'role_id'])
            ->addForeignKey(['membership_id'], 'auth_memberships', ['id'], ['delete' => 'CASCADE', 'update' => 'CASCADE'])
            ->addForeignKey(['role_id'], 'auth_roles', ['id'], ['delete' => 'CASCADE', 'update' => 'CASCADE'])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_membership_roles')->drop();
    }
}
