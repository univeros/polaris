<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_refresh_tokens` table behind
 * {@see \Univeros\Polaris\Entity\RefreshToken}.
 *
 * Driver-agnostic: only Cycle's abstract column types are used, so the same
 * migration applies cleanly on every supported database engine.
 */
final class M20260607000002CreateAuthRefreshTokens extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_refresh_tokens')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('user_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('organization_id', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('family_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('parent_id', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('token_hash', 'string', ['size' => 64, 'nullable' => false])
            ->addColumn('user_agent', 'string', ['size' => 255, 'nullable' => true])
            ->addColumn('ip', 'string', ['size' => 45, 'nullable' => true])
            ->addColumn('expires_at', 'datetime', ['nullable' => false])
            ->addColumn('last_used_at', 'datetime', ['nullable' => true])
            ->addColumn('revoked_at', 'datetime', ['nullable' => true])
            ->addColumn('revoked_reason', 'string', ['size' => 32, 'nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['token_hash'], ['name' => 'auth_refresh_tokens_token_hash_unique', 'unique' => true])
            ->addIndex(['user_id', 'revoked_at'], ['name' => 'auth_refresh_tokens_user_index', 'unique' => false])
            ->addIndex(['family_id'], ['name' => 'auth_refresh_tokens_family_index', 'unique' => false])
            ->addIndex(['expires_at'], ['name' => 'auth_refresh_tokens_expires_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_refresh_tokens')->drop();
    }
}
