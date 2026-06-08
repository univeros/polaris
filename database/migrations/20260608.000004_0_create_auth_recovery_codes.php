<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_recovery_codes` table behind {@see \Univeros\Polaris\Entity\RecoveryCode}.
 *
 * Driver-agnostic: only Cycle's abstract column types are used, so the same migration applies
 * cleanly on every supported database engine.
 */
final class M20260608000004CreateAuthRecoveryCodes extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_recovery_codes')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('user_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('code_hash', 'string', ['size' => 64, 'nullable' => false])
            ->addColumn('used_at', 'datetime', ['nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['user_id', 'used_at'], ['name' => 'auth_recovery_codes_user_used_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_recovery_codes')->drop();
    }
}
