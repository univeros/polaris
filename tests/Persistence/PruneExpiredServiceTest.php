<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Maintenance\PruneExpiredService;

use function bin2hex;
use function is_array;
use function is_string;
use function random_bytes;

/**
 * Verifies the #40 {@see PruneExpiredService} against a real driver: consumed/expired transient
 * rows are bulk-deleted, live rows survive, recently expired refresh tokens are kept inside the
 * forensic grace window, the audit log is untouched, and a second run is a no-op.
 */
final class PruneExpiredServiceTest extends DatabaseTestCase
{
    public const string NOW = '2026-06-10 12:00:00';

    public function testPrunesDeadRowsAndKeepsLiveOnes(): void
    {
        // OTP challenges: consumed, expired, and live.
        $this->seedOtpChallenge(consumedAt: self::NOW, expiresAt: '2026-06-10 13:00:00');
        $this->seedOtpChallenge(consumedAt: null, expiresAt: '2026-06-10 11:00:00');
        $live = $this->seedOtpChallenge(consumedAt: null, expiresAt: '2026-06-10 13:00:00');

        // Email verifications / password resets: one dead, one live each.
        $this->seedChallengeRow('auth_email_verifications', expiresAt: '2026-06-09 00:00:00');
        $liveVerification = $this->seedChallengeRow('auth_email_verifications', expiresAt: '2026-06-11 00:00:00');
        $this->seedChallengeRow('auth_password_resets', expiresAt: '2026-06-09 00:00:00');

        // Refresh tokens: long-expired (pruned), expired within grace (kept), live (kept).
        $this->seedRefreshToken(expiresAt: '2026-06-01 00:00:00');
        $inGrace = $this->seedRefreshToken(expiresAt: '2026-06-08 00:00:00');
        $liveToken = $this->seedRefreshToken(expiresAt: '2026-06-20 00:00:00');

        // Audit rows are never pruned.
        $this->seedAuditRow();

        $deleted = $this->service()->prune();

        self::assertSame(2, $deleted['auth_otp_challenges']);
        self::assertSame(1, $deleted['auth_email_verifications']);
        self::assertSame(1, $deleted['auth_password_resets']);
        self::assertSame(1, $deleted['auth_refresh_tokens']);

        self::assertSame([$live], $this->ids('auth_otp_challenges'));
        self::assertSame([$liveVerification], $this->ids('auth_email_verifications'));
        self::assertSame([], $this->ids('auth_password_resets'));
        self::assertEqualsCanonicalizing([$inGrace, $liveToken], $this->ids('auth_refresh_tokens'));
        self::assertCount(1, $this->ids('auth_audit_log'));
    }

    public function testASecondRunIsANoOp(): void
    {
        $this->seedOtpChallenge(consumedAt: self::NOW, expiresAt: '2026-06-10 13:00:00');

        $this->service()->prune();
        $second = $this->service()->prune();

        self::assertSame(0, $second['auth_otp_challenges']);
        self::assertSame(0, $second['auth_email_verifications']);
        self::assertSame(0, $second['auth_password_resets']);
        self::assertSame(0, $second['auth_refresh_tokens']);
    }

    private function service(): PruneExpiredService
    {
        $clock = new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable(PruneExpiredServiceTest::NOW);
            }
        };

        return new PruneExpiredService($this->orm, $clock);
    }

    private function seedOtpChallenge(?string $consumedAt, string $expiresAt): string
    {
        $id = Uuid::v7()->toRfc4122();
        $this->connection()->insert('auth_otp_challenges')->values([
            'id' => $id,
            'user_id' => Uuid::v7()->toRfc4122(),
            'purpose' => 'login',
            'channel' => 'email',
            'attempts' => 0,
            'consumed_at' => $consumedAt === null ? null : new DateTimeImmutable($consumedAt),
            'expires_at' => new DateTimeImmutable($expiresAt),
            'created_at' => new DateTimeImmutable('2026-06-10 10:00:00'),
        ])->run();

        return $id;
    }

    private function seedChallengeRow(string $table, string $expiresAt): string
    {
        $id = Uuid::v7()->toRfc4122();
        $this->connection()->insert($table)->values([
            'id' => $id,
            'user_id' => Uuid::v7()->toRfc4122(),
            'email' => 'someone@example.com',
            'token_hash' => bin2hex(random_bytes(32)),
            'expires_at' => new DateTimeImmutable($expiresAt),
            'created_at' => new DateTimeImmutable('2026-06-10 10:00:00'),
        ])->run();

        return $id;
    }

    private function seedRefreshToken(string $expiresAt): string
    {
        $id = Uuid::v7()->toRfc4122();
        $this->connection()->insert('auth_refresh_tokens')->values([
            'id' => $id,
            'user_id' => Uuid::v7()->toRfc4122(),
            'family_id' => Uuid::v7()->toRfc4122(),
            'token_hash' => bin2hex(random_bytes(32)),
            'expires_at' => new DateTimeImmutable($expiresAt),
            'created_at' => new DateTimeImmutable('2026-06-01 00:00:00'),
        ])->run();

        return $id;
    }

    private function seedAuditRow(): void
    {
        $this->connection()->insert('auth_audit_log')->values([
            'id' => Uuid::v7()->toRfc4122(),
            'event' => 'user.logged_in',
            'metadata' => '{}',
            'created_at' => new DateTimeImmutable('2020-01-01 00:00:00'), // ancient — still kept
        ])->run();
    }

    /**
     * @return list<string>
     */
    private function ids(string $table): array
    {
        $ids = [];
        foreach ($this->connection()->select('id')->from($table)->fetchAll() as $row) {
            if (is_array($row) && is_string($row['id'] ?? null)) {
                $ids[] = $row['id'];
            }
        }

        return $ids;
    }
}
