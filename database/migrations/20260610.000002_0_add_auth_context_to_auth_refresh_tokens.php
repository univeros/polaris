<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Adds the session's authentication context to `auth_refresh_tokens` — `mfa`, `amr`
 * (comma-joined method references), and `auth_time` (unix timestamp of the last full
 * authentication). Recorded at login/step-up and mirrored into every refreshed access token, so
 * a refresh no longer downgrades `mfa` to false (issue #97). Additive with defaults, so it
 * applies to existing rows without backfill: pre-existing sessions read `mfa=false`/`amr=pwd`,
 * exactly what they read before this migration.
 *
 * Uses Cycle's abstract column types only, so the DDL renders correctly on every supported
 * driver.
 */
final class M20260610000002AddAuthContextToAuthRefreshTokens extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_refresh_tokens')
            ->addColumn('mfa', 'boolean', ['nullable' => false, 'default' => false])
            ->addColumn('amr', 'string', ['size' => 64, 'nullable' => true])
            ->addColumn('auth_time', 'integer', ['nullable' => true])
            ->update();
    }

    public function down(): void
    {
        $this->table('auth_refresh_tokens')
            ->dropColumn('mfa')
            ->dropColumn('amr')
            ->dropColumn('auth_time')
            ->update();
    }
}
