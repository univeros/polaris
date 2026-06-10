<?php

declare(strict_types=1);

namespace Univeros\Polaris\Notification;

use Altair\Persistence\Contracts\RepositoryInterface;
use Psr\Log\LoggerInterface;
use Throwable;
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

use function str_ends_with;

/**
 * PSR-14 listener turning user-facing domain events into notifications via the
 * {@see OtpMailerInterface} port (`docs/auth/events.md`, "notify user" column). Subscribe it to
 * the host's dispatcher alongside the audit listener; the adapter renders the logical template.
 *
 * Token-carrying events (registration, password reset, invitation) forward their single-use
 * plaintext token as the mail payload — that is the one place those tokens are allowed to travel.
 * Events that only carry a user id (locked, password changed, MFA changes) look the recipient up;
 * unknown users and anonymized tombstones are skipped. SMS delivery stays inside the OTP flow
 * ({@see \Univeros\Polaris\Mfa\OtpService}), which sends codes through the SMS port directly.
 *
 * **Fail-open:** like the audit trail, a notification failure must never break the operation that
 * triggered it — it is logged (PSR-3) and swallowed.
 */
final class NotificationListener
{
    private const string TOMBSTONE_EMAIL_SUFFIX = '@deleted.invalid';

    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(
        private readonly OtpMailerInterface $mailer,
        private readonly RepositoryInterface $users,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function __invoke(object $event): void
    {
        try {
            $this->notify($event);
        } catch (Throwable $exception) {
            $this->logger->error('Notification failed for {event}: {reason}', [
                'event' => $event::class,
                'reason' => $exception->getMessage(),
                'exception' => $exception,
            ]);
        }
    }

    private function notify(object $event): void
    {
        match (true) {
            $event instanceof UserRegistered
                => $this->mailer->send($event->email, 'verify_email', ['token' => $event->verificationToken]),
            $event instanceof PasswordResetRequested
                => $this->mailer->send($event->email, 'password_reset', ['token' => $event->resetToken]),
            $event instanceof MemberInvited
                => $this->mailer->send($event->email, 'org_invite', [
                    'token' => $event->inviteToken,
                    'organization_id' => $event->organizationId,
                ]),
            $event instanceof UserLocked
                => $this->mail($event->userId, 'account_locked', ['ip' => $event->ip]),
            $event instanceof PasswordChanged
                => $this->mail($event->userId, 'password_changed', ['method' => $event->method]),
            $event instanceof MfaEnrolled
                => $this->mail($event->userId, 'mfa_enrolled', ['factor_id' => $event->factorId]),
            $event instanceof MfaFactorRemoved
                => $this->mail($event->userId, 'mfa_factor_removed', ['factor_id' => $event->factorId]),
            $event instanceof MfaRecoveryRegenerated
                => $this->mail($event->userId, 'recovery_codes_regenerated', []),
            $event instanceof MfaRecoveryUsed
                => $this->mail($event->userId, 'recovery_code_used', ['remaining' => $event->remaining]),
            default => null,
        };
    }

    /**
     * Send to a user looked up by id; silently skipped for unknown users and tombstones.
     *
     * @param array<string, mixed> $context
     */
    private function mail(string $userId, string $template, array $context): void
    {
        $user = $this->users->find($userId);
        if (!$user instanceof User || str_ends_with($user->email, self::TOMBSTONE_EMAIL_SUFFIX)) {
            return;
        }

        $this->mailer->send($user->email, $template, $context);
    }
}
