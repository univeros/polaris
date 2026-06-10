<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_audit_log` table behind {@see \Univeros\Polaris\Entity\AuditLogEntry}.
 *
 * Append-only security trail: one row per PSR-14 domain event with actor/org/network context and
 * a JSON metadata blob that never contains secrets. Indexed by actor, org, and event name for the
 * queries an investigation actually runs. Driver-agnostic: only Cycle's abstract column types are
 * used, so the same migration applies cleanly on every supported database engine.
 */
final class M20260610000001CreateAuthAuditLog extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_audit_log')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('actor_user_id', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('organization_id', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('event', 'string', ['size' => 80, 'nullable' => false])
            ->addColumn('ip', 'string', ['size' => 45, 'nullable' => true])
            ->addColumn('user_agent', 'string', ['size' => 255, 'nullable' => true])
            ->addColumn('metadata', 'json', ['nullable' => false])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(['actor_user_id', 'created_at'], ['name' => 'auth_audit_log_actor_index', 'unique' => false])
            ->addIndex(['organization_id', 'created_at'], ['name' => 'auth_audit_log_org_index', 'unique' => false])
            ->addIndex(['event', 'created_at'], ['name' => 'auth_audit_log_event_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_audit_log')->drop();
    }
}
