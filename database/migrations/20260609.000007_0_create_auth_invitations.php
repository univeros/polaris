<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_invitations` table behind {@see \Univeros\Polaris\Entity\Invitation}.
 *
 * `unique(token_hash)` enforces a single live invitation per emailed token (stored only as its
 * HMAC hash); `role_ids` is a portable JSON column holding the roles to grant on acceptance.
 * Driver-agnostic: only Cycle's abstract column types are used, so the same migration applies
 * cleanly on every supported database engine.
 */
final class M20260609000007CreateAuthInvitations extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_invitations')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('organization_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('email', 'string', ['size' => 320, 'nullable' => false])
            ->addColumn('role_ids', 'json', ['nullable' => false])
            ->addColumn('token_hash', 'string', ['size' => 64, 'nullable' => false])
            ->addColumn('invited_by', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('expires_at', 'datetime', ['nullable' => false])
            ->addColumn('accepted_at', 'datetime', ['nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['token_hash'], ['name' => 'auth_invitations_token_hash_unique', 'unique' => true])
            ->addIndex(['organization_id'], ['name' => 'auth_invitations_org_index', 'unique' => false])
            ->addIndex(['email'], ['name' => 'auth_invitations_email_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_invitations')->drop();
    }
}
