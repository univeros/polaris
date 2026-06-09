<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_permissions` table behind {@see \Univeros\Polaris\Entity\Permission}.
 *
 * `unique(key)` enforces a single catalog entry per capability key. Driver-agnostic: only Cycle's
 * abstract column types are used, so the same migration applies cleanly on every supported engine.
 */
final class M20260609000004CreateAuthPermissions extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_permissions')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('key', 'string', ['size' => 120, 'nullable' => false])
            ->addColumn('description', 'string', ['size' => 255, 'nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['key'], ['name' => 'auth_permissions_key_unique', 'unique' => true])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_permissions')->drop();
    }
}
