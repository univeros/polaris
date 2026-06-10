<?php

declare(strict_types=1);

namespace Univeros\Polaris\Maintenance;

use Cycle\Database\DatabaseInterface;
use Cycle\ORM\ORMInterface;
use DateInterval;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Entity\EmailVerification;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Entity\PasswordReset;
use Univeros\Polaris\Entity\RefreshToken;

/**
 * Prunes the expired/consumed transient rows so the auth tables stay small
 * (`docs/auth/data-model.md` §3). The host schedules it — `bin/altair` job, cron, whatever exists;
 * Polaris does not assume a scheduler. Safe to run repeatedly: every delete is bounded by
 * conditions that only ever match dead rows.
 *
 * - `auth_otp_challenges`, `auth_email_verifications`, `auth_password_resets`: consumed or expired.
 * - `auth_refresh_tokens`: expired longer than the grace window ago — recently dead tokens stay
 *   for replay/reuse-detection forensics (default 7 days).
 * - `auth_audit_log` is **not** touched: its retention is host policy (default 1 year + archive).
 *
 * Deletes run as single bulk statements through the entities' own database handles (no
 * row-by-row hydration), so a large backlog prunes in one pass.
 */
final class PruneExpiredService
{
    public const string DEFAULT_REFRESH_GRACE = 'P7D';

    public function __construct(
        private readonly ORMInterface $orm,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * Delete dead transient rows and report how many went, per table.
     *
     * @param DateInterval|null $refreshGrace how long expired refresh tokens are kept for
     *                                        forensics (default 7 days)
     *
     * @return array<string, int> table name => rows deleted
     */
    public function prune(?DateInterval $refreshGrace = null): array
    {
        $now = $this->clock->now();
        $refreshCutoff = $now->sub($refreshGrace ?? new DateInterval(self::DEFAULT_REFRESH_GRACE));

        $deleted = [];
        foreach ([OtpChallenge::class, EmailVerification::class, PasswordReset::class] as $entity) {
            $database = $this->databaseFor($entity);
            $table = $this->tableFor($entity);
            $deleted[$table] = $database->delete($table)
                ->where(static function ($query) use ($now): void {
                    $query->where('consumed_at', '!=', null)->orWhere('expires_at', '<', $now);
                })
                ->run();
        }

        $database = $this->databaseFor(RefreshToken::class);
        $deleted['auth_refresh_tokens'] = $database->delete('auth_refresh_tokens')
            ->where('expires_at', '<', $refreshCutoff)
            ->run();

        return $deleted;
    }

    /**
     * @param class-string $entity
     */
    private function databaseFor(string $entity): DatabaseInterface
    {
        $source = $this->orm->getSource($entity);

        return $source->getDatabase();
    }

    /**
     * @param class-string $entity
     */
    private function tableFor(string $entity): string
    {
        return $this->orm->getSource($entity)->getTable();
    }
}
