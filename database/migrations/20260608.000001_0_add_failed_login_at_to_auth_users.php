<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Adds `auth_users.failed_login_at` — the timestamp of the most recent failed login, which
 * anchors the sliding lockout window introduced in issue #16 (failures older than
 * `auth.lockout.window` no longer count toward a lock). Additive and nullable, so it applies
 * to existing rows without backfill.
 *
 * Uses Cycle's abstract column types only, so the DDL renders correctly on every supported
 * driver.
 */
final class M20260608000001AddFailedLoginAtToAuthUsers extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_users')
            ->addColumn('failed_login_at', 'datetime', ['nullable' => true])
            ->update();
    }

    public function down(): void
    {
        $this->table('auth_users')
            ->dropColumn('failed_login_at')
            ->update();
    }
}
