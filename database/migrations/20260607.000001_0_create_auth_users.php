<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_users` table behind {@see \Univeros\Polaris\Entity\User}.
 *
 * Uses Cycle's abstract column types only, so `bin/altair db:migrate` renders the
 * correct DDL on PostgreSQL, MySQL, SQL Server, and any other supported driver —
 * the migration is not tied to a single database engine.
 */
final class M20260607000001CreateAuthUsers extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_users')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('email', 'string', ['size' => 320, 'nullable' => false])
            ->addColumn('email_verified_at', 'datetime', ['nullable' => true])
            ->addColumn('password_hash', 'string', ['size' => 255, 'nullable' => true])
            ->addColumn('display_name', 'string', ['size' => 120, 'nullable' => true])
            ->addColumn('status', 'string', ['size' => 16, 'nullable' => false, 'default' => 'active'])
            ->addColumn('mfa_enforced', 'boolean', ['nullable' => false, 'default' => false])
            ->addColumn('failed_login_count', 'integer', ['nullable' => false, 'default' => 0])
            ->addColumn('locked_until', 'datetime', ['nullable' => true])
            ->addColumn('last_login_at', 'datetime', ['nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->addColumn('updated_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['email'], ['name' => 'auth_users_email_unique', 'unique' => true])
            ->addIndex(['status'], ['name' => 'auth_users_status_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_users')->drop();
    }
}
