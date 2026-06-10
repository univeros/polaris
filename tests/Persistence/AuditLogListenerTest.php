<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Univeros\Polaris\Entity\AuditLogEntry;
use Univeros\Polaris\Event\MemberInvited;
use Univeros\Polaris\Event\MemberRolesChanged;
use Univeros\Polaris\Event\MemberStatusChanged;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Event\MfaVerified;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Event\OrganizationDeleted;
use Univeros\Polaris\Event\OrganizationSwitched;
use Univeros\Polaris\Event\OrganizationUpdated;
use Univeros\Polaris\Event\OtpVerifyFailed;
use Univeros\Polaris\Event\PasswordResetRequested;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\RoleCreated;
use Univeros\Polaris\Event\RoleDeleted;
use Univeros\Polaris\Event\RoleUpdated;
use Univeros\Polaris\Event\SessionsRevoked;
use Univeros\Polaris\Event\UserDisabled;
use Univeros\Polaris\Event\UserLocked;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Event\UserLoginFailed;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Observability\AuditLogListener;
use Univeros\Polaris\Persistence\AuditLogRepository;

use function is_array;
use function json_decode;
use function str_contains;
use function usort;

/**
 * Verifies the #38 {@see AuditLogListener} against a real driver: each domain event becomes one
 * append-only `auth_audit_log` row carrying the event name, actor/org context, IP where the event
 * has one, and whitelisted metadata — and, above all, that **secret-carrying events never leak
 * their tokens** into a row. Unrecognized events are ignored.
 */
final class AuditLogListenerTest extends DatabaseTestCase
{
    public const string NOW = '2026-06-10 12:00:00';

    public function testRecordsEventNameActorAndMetadata(): void
    {
        $this->listener()(new UserLoggedIn('user-1', 'session-9', '203.0.113.7', 'Browser/1.0', ['pwd', 'otp']));

        $rows = $this->rows();
        self::assertCount(1, $rows);
        self::assertSame('user.logged_in', $rows[0]->event);
        self::assertSame('user-1', $rows[0]->actorUserId);
        self::assertNull($rows[0]->organizationId);
        self::assertSame('203.0.113.7', $rows[0]->ip);
        self::assertSame('Browser/1.0', $rows[0]->userAgent, 'the client user agent reaches the row (#90)');
        self::assertSame(['session_id' => 'session-9', 'amr' => ['pwd', 'otp']], $this->metadata($rows[0]));
        self::assertSame(self::NOW, $rows[0]->createdAt->format('Y-m-d H:i:s'));
    }

    public function testRecordsLoginFailureReasonAndLockExpiry(): void
    {
        $listener = $this->listener();
        $listener(new UserLoginFailed('user-1', '203.0.113.7', 'Browser/1.0', UserLoginFailed::REASON_INVALID_CREDENTIALS));
        $listener(new UserLocked('user-1', '203.0.113.7', new DateTimeImmutable('2026-06-10 12:15:00 +00:00')));

        $rows = $this->rows();
        self::assertCount(2, $rows);
        self::assertSame('user.login_failed', $rows[0]->event);
        self::assertSame('Browser/1.0', $rows[0]->userAgent);
        self::assertSame(['reason' => 'invalid_credentials'], $this->metadata($rows[0]));
        self::assertSame('user.locked', $rows[1]->event);
        self::assertSame(['until' => '2026-06-10T12:15:00+00:00'], $this->metadata($rows[1]));
    }

    public function testRecordsSessionRevocationScaleAndReason(): void
    {
        $this->listener()(new SessionsRevoked('user-1', '203.0.113.7', 3, 'logout'));

        $rows = $this->rows();
        self::assertCount(1, $rows);
        self::assertSame('auth.sessions_revoked', $rows[0]->event);
        self::assertSame(['count' => 3, 'reason' => 'logout'], $this->metadata($rows[0]));
    }

    public function testRecordsMfaFactorContext(): void
    {
        $listener = $this->listener();
        $listener(new MfaEnrolled('user-1', 'factor-1', 'totp'));
        $listener(new MfaVerifyFailed('user-1', 'factor-1', 'sms'));
        $listener(new OtpVerifyFailed('user-1', 'factor-1', 4));

        $rows = $this->rows();
        self::assertCount(3, $rows);
        self::assertSame(['factor_id' => 'factor-1', 'type' => 'totp'], $this->metadata($rows[0]));
        self::assertSame(['factor_id' => 'factor-1', 'type' => 'sms'], $this->metadata($rows[1]));
        self::assertSame(['factor_id' => 'factor-1', 'attempts_left' => 4], $this->metadata($rows[2]));
    }

    public function testRecordsOrgAndRoleLifecycleEvents(): void
    {
        $listener = $this->listener();
        $listener(new OrganizationSwitched('user-1', 'org-1', 'org-2'));
        $listener(new OrganizationUpdated('org-2', 'admin-1'));
        $listener(new RoleCreated('org-2', 'role-1', 'admin-1'));
        $listener(new RoleUpdated('org-2', 'role-1', 'admin-1'));
        $listener(new RoleDeleted('org-2', 'role-1', 'admin-1'));

        $rows = $this->rows();
        self::assertCount(5, $rows);

        self::assertSame('auth.org_switched', $rows[0]->event);
        self::assertSame('user-1', $rows[0]->actorUserId);
        self::assertSame('org-2', $rows[0]->organizationId, 'the new org is the row context');
        self::assertSame(['from_organization_id' => 'org-1'], $this->metadata($rows[0]));

        self::assertSame('org.updated', $rows[1]->event);
        self::assertSame('admin-1', $rows[1]->actorUserId);
        self::assertSame('org-2', $rows[1]->organizationId);

        foreach ([2 => 'role.created', 3 => 'role.updated', 4 => 'role.deleted'] as $i => $name) {
            self::assertSame($name, $rows[$i]->event);
            self::assertSame('admin-1', $rows[$i]->actorUserId);
            self::assertSame('org-2', $rows[$i]->organizationId);
            self::assertSame(['role_id' => 'role-1'], $this->metadata($rows[$i]));
        }
    }

    public function testRecordsOrgContextAndAdminActor(): void
    {
        $listener = $this->listener();
        $listener(new OrganizationDeleted('org-1', 'admin-1'));
        $listener(new UserDisabled('target-1', 'admin-1'));
        $listener(new RefreshReuseDetected('user-1', 'family-3', '198.51.100.2', 'Stolen/1.0'));

        $rows = $this->rows();
        self::assertCount(3, $rows);

        self::assertSame('org.deleted', $rows[0]->event);
        self::assertSame('admin-1', $rows[0]->actorUserId);
        self::assertSame('org-1', $rows[0]->organizationId);

        self::assertSame('user.disabled', $rows[1]->event);
        self::assertSame('admin-1', $rows[1]->actorUserId);
        self::assertSame(['user_id' => 'target-1'], $this->metadata($rows[1]));

        self::assertSame('auth.refresh_reuse_detected', $rows[2]->event);
        self::assertSame(['family_id' => 'family-3'], $this->metadata($rows[2]));
        self::assertSame('198.51.100.2', $rows[2]->ip);
        self::assertSame('Stolen/1.0', $rows[2]->userAgent);
    }

    public function testSecretCarryingEventsNeverLeakTheirTokens(): void
    {
        $listener = $this->listener();
        $listener(new UserRegistered('user-1', 'new@example.com', 'verification-secret-token'));
        $listener(new PasswordResetRequested('user-1', 'new@example.com', 'reset-secret-token'));
        $listener(new MemberInvited('org-1', 'invitee@example.com', 'inviter-1', 'invite-secret-token'));

        $rows = $this->rows();
        self::assertCount(3, $rows);
        foreach ($rows as $row) {
            self::assertFalse(str_contains($row->metadata, 'secret-token'), "Secret leaked into $row->event metadata");
        }

        // The whitelisted, non-secret context is still there.
        self::assertSame(['email' => 'new@example.com'], $this->metadata($rows[0]));
        self::assertSame('inviter-1', $rows[2]->actorUserId);
        self::assertSame('org-1', $rows[2]->organizationId);
    }

    public function testRecordsMembershipManagementEvents(): void
    {
        $listener = $this->listener();
        $listener(new MemberRolesChanged('org-1', 'member-1', ['admin', 'support'], 'owner-1'));
        $listener(new MemberStatusChanged('org-1', 'member-1', 'suspended', 'owner-1'));

        $rows = $this->rows();
        self::assertCount(2, $rows);
        self::assertSame('member.roles_changed', $rows[0]->event);
        self::assertSame('owner-1', $rows[0]->actorUserId);
        self::assertSame('org-1', $rows[0]->organizationId);
        self::assertSame(['user_id' => 'member-1', 'role_slugs' => ['admin', 'support']], $this->metadata($rows[0]));
        self::assertSame('member.status_changed', $rows[1]->event);
        self::assertSame(['user_id' => 'member-1', 'status' => 'suspended'], $this->metadata($rows[1]));
    }

    public function testRecordsARecoveryCodeVerificationWithoutAFactor(): void
    {
        $this->listener()(new MfaVerified('user-1', null));

        $rows = $this->rows();
        self::assertCount(1, $rows);
        self::assertSame('mfa.verified', $rows[0]->event);
        self::assertSame(['factor_id' => null], $this->metadata($rows[0]));
    }

    public function testAFailedAuditWriteIsSwallowedNotPropagated(): void
    {
        $broken = new class () implements UnitOfWorkInterface {
            public function persist(object $entity): void
            {
            }

            public function remove(object $entity): void
            {
            }

            public function flush(): void
            {
                throw new RuntimeException('database is down');
            }

            public function clear(): void
            {
            }
        };
        $clock = new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable(AuditLogListenerTest::NOW);
            }
        };

        // Fail-open: the user-facing operation already committed; audit loss must not break it.
        (new AuditLogListener($broken, $clock, new NullLogger()))(new UserLoggedIn('user-1', 'session-1', null));

        $this->expectNotToPerformAssertions();
    }

    public function testIgnoresUnknownEvents(): void
    {
        $this->listener()(new class () {
        });

        self::assertCount(0, $this->rows());
    }

    private function listener(): AuditLogListener
    {
        $clock = new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable(AuditLogListenerTest::NOW);
            }
        };

        return new AuditLogListener($this->unitOfWork, $clock, new NullLogger());
    }

    /**
     * @return list<AuditLogEntry>
     */
    private function rows(): array
    {
        $rows = [];
        foreach ((new AuditLogRepository($this->orm, $this->unitOfWork))->findAll() as $row) {
            $rows[] = $row;
        }
        usort($rows, static fn(AuditLogEntry $a, AuditLogEntry $b): int => $a->id <=> $b->id);

        return $rows;
    }

    /**
     * @return array<string, mixed>
     */
    private function metadata(AuditLogEntry $entry): array
    {
        $decoded = json_decode($entry->metadata, true);

        return is_array($decoded) ? $decoded : [];
    }
}
