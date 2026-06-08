<?php

declare(strict_types=1);

namespace Univeros\Polaris\Database\Migrations;

use Cycle\Migrations\Migration;

/**
 * Creates the `auth_otp_challenges` table behind {@see \Univeros\Polaris\Entity\OtpChallenge}.
 *
 * Driver-agnostic: only Cycle's abstract column types are used, so the same migration applies
 * cleanly on every supported database engine.
 */
final class M20260608000003CreateAuthOtpChallenges extends Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        $this->table('auth_otp_challenges')
            ->addColumn('id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('user_id', 'string', ['size' => 36, 'nullable' => false])
            ->addColumn('factor_id', 'string', ['size' => 36, 'nullable' => true])
            ->addColumn('purpose', 'string', ['size' => 20, 'nullable' => false])
            ->addColumn('channel', 'string', ['size' => 16, 'nullable' => false])
            ->addColumn('code_hash', 'string', ['size' => 64, 'nullable' => true])
            ->addColumn('destination', 'string', ['size' => 320, 'nullable' => true])
            ->addColumn('attempts', 'integer', ['nullable' => false, 'default' => 0])
            ->addColumn('max_attempts', 'integer', ['nullable' => false, 'default' => 5])
            ->addColumn('expires_at', 'datetime', ['nullable' => false])
            ->addColumn('consumed_at', 'datetime', ['nullable' => true])
            ->addColumn('ip', 'string', ['size' => 45, 'nullable' => true])
            ->addColumn('created_at', 'datetime', ['nullable' => false])
            ->setPrimaryKeys(['id'])
            ->addIndex(
                ['user_id', 'purpose', 'consumed_at'],
                ['name' => 'auth_otp_challenges_user_purpose_index', 'unique' => false],
            )
            ->addIndex(['expires_at'], ['name' => 'auth_otp_challenges_expires_index', 'unique' => false])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_otp_challenges')->drop();
    }
}
