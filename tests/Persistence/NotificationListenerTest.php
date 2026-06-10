<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use DateTimeImmutable;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\MemberInvited;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Event\MfaFactorRemoved;
use Univeros\Polaris\Event\MfaRecoveryRegenerated;
use Univeros\Polaris\Event\MfaRecoveryUsed;
use Univeros\Polaris\Event\PasswordChanged;
use Univeros\Polaris\Event\PasswordResetRequested;
use Univeros\Polaris\Event\UserLocked;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Notification\NotificationListener;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Tests\Support\RecordingOtpMailer;

use function str_repeat;

/**
 * Verifies the #39 {@see NotificationListener}: user-facing events become mailer-port sends with
 * the right template and context, token-carrying events forward their token as the payload,
 * id-only events resolve the recipient (skipping unknown users and anonymized tombstones), and a
 * failing adapter never breaks the triggering operation.
 */
final class NotificationListenerTest extends DatabaseTestCase
{
    public function testTokenCarryingEventsMailTheTokenDirectly(): void
    {
        $mailer = new RecordingOtpMailer();
        $listener = $this->listener($mailer);

        $listener(new UserRegistered('user-1', 'new@example.com', 'verify-token'));
        $listener(new PasswordResetRequested('user-1', 'new@example.com', 'reset-token'));
        $listener(new MemberInvited('org-1', 'invitee@example.com', 'inviter-1', 'invite-token'));

        self::assertCount(3, $mailer->sent);
        self::assertSame(['to' => 'new@example.com', 'template' => 'verify_email', 'context' => ['token' => 'verify-token']], $mailer->sent[0]);
        self::assertSame('password_reset', $mailer->sent[1]['template']);
        self::assertSame('reset-token', $mailer->sent[1]['context']['token']);
        self::assertSame('invitee@example.com', $mailer->sent[2]['to']);
        self::assertSame('org-1', $mailer->sent[2]['context']['organization_id']);
    }

    public function testIdOnlyEventsResolveTheRecipient(): void
    {
        $userId = $this->seedUser('locked@example.com');
        $mailer = new RecordingOtpMailer();
        $listener = $this->listener($mailer);

        $listener(new UserLocked($userId, '203.0.113.7'));
        $listener(new PasswordChanged($userId, 'reset'));
        $listener(new MfaEnrolled($userId, 'factor-1'));
        $listener(new MfaFactorRemoved($userId, 'factor-1'));
        $listener(new MfaRecoveryRegenerated($userId));
        $listener(new MfaRecoveryUsed($userId, 7));

        self::assertCount(6, $mailer->sent);
        self::assertSame(['to' => 'locked@example.com', 'template' => 'account_locked', 'context' => ['ip' => '203.0.113.7']], $mailer->sent[0]);
        self::assertSame('password_changed', $mailer->sent[1]['template']);
        self::assertSame('mfa_enrolled', $mailer->sent[2]['template']);
        self::assertSame('mfa_factor_removed', $mailer->sent[3]['template']);
        self::assertSame('recovery_codes_regenerated', $mailer->sent[4]['template']);
        self::assertSame(['to' => 'locked@example.com', 'template' => 'recovery_code_used', 'context' => ['remaining' => 7]], $mailer->sent[5]);
    }

    public function testUnknownUsersAndTombstonesAreSkipped(): void
    {
        $tombstone = $this->seedUser(str_repeat('a', 64) . '@deleted.invalid');
        $mailer = new RecordingOtpMailer();
        $listener = $this->listener($mailer);

        $listener(new UserLocked(Uuid::v7()->toRfc4122(), null));
        $listener(new UserLocked($tombstone, null));
        $listener(new PasswordChanged($tombstone, 'change'));
        $listener(new MfaRecoveryUsed($tombstone, 3));

        self::assertCount(0, $mailer->sent);
    }

    public function testAFailingMailerIsSwallowedNotPropagated(): void
    {
        $broken = new class () implements OtpMailerInterface {
            public function send(string $toEmail, string $template, array $context): void
            {
                throw new \RuntimeException('smtp is down');
            }
        };

        $listener = new NotificationListener($broken, new UserRepository($this->orm, $this->unitOfWork), new NullLogger());
        $listener(new UserRegistered('user-1', 'new@example.com', 'token'));

        $this->expectNotToPerformAssertions();
    }

    public function testIgnoresUnrelatedEvents(): void
    {
        $mailer = new RecordingOtpMailer();
        $this->listener($mailer)(new class () {
        });

        self::assertCount(0, $mailer->sent);
    }

    private function listener(RecordingOtpMailer $mailer): NotificationListener
    {
        return new NotificationListener($mailer, new UserRepository($this->orm, $this->unitOfWork), new NullLogger());
    }

    private function seedUser(string $email): string
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->createdAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        return $user->id;
    }
}
