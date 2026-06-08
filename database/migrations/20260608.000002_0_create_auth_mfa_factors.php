<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_mfa_factors` table behind {@see \Univeros\Polaris\Entity\MfaFactor}.
 *
 * Driver-agnostic: only Cycle's abstract column types are used, so the same migration applies
 * cleanly on every supported database engine.
 */
final class M20260608000002CreateAuthMfaFactors extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_mfa_factors')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('user_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('type', 'string', ['size' => 16, 'nullable' => false])
            ->addColumn('label', 'string', ['size' => 80, 'nullable' => true])
            ->addColumn('secret_encrypted', 'text', ['nullable' => true])
            ->addColumn('phone_e164', 'string', ['size' => 20, 'nullable' => true])
            ->addColumn('email', 'string', ['size' => 320, 'nullable' => true])
            ->addColumn('is_default', 'boolean', ['nullable' => false, 'default' => false])
            ->addColumn('confirmed_at', 'datetime', ['nullable' => true])
            ->addColumn('last_used_at', 'datetime', ['nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->addColumn('updated_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['user_id', 'type'], ['name' => 'auth_mfa_factors_user_type_index', 'unique' => false])
            ->addIndex(['user_id', 'confirmed_at'], ['name' => 'auth_mfa_factors_user_confirmed_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_mfa_factors')->drop();
    }
}
