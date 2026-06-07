<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_email_verifications` table behind
 * {@see \Univeros\Polaris\Entity\EmailVerification}.
 *
 * Driver-agnostic: only Cycle's abstract column types are used, so the same
 * migration applies cleanly on every supported database engine.
 */
final class M20260607000003CreateAuthEmailVerifications extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_email_verifications')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('user_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('email', 'string', ['size' => 320, 'nullable' => false])
            ->addColumn('token_hash', 'string', ['size' => 64, 'nullable' => false])
            ->addColumn('expires_at', 'datetime', ['nullable' => false])
            ->addColumn('consumed_at', 'datetime', ['nullable' => true])
            ->addColumn('ip', 'string', ['size' => 45, 'nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['token_hash'], ['name' => 'auth_email_verifications_token_hash_unique', 'unique' => true])
            ->addIndex(['user_id'], ['name' => 'auth_email_verifications_user_index', 'unique' => false])
            ->addIndex(['expires_at'], ['name' => 'auth_email_verifications_expires_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_email_verifications')->drop();
    }
}
