<?php

declare(strict_types=1);

namespace Univeros\Polaris\Observability;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use JsonException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Univeros\Polaris\Entity\AuditLogEntry;
use Univeros\Polaris\Event\MemberInvited;
use Univeros\Polaris\Event\MemberJoined;
use Univeros\Polaris\Event\MemberRemoved;
use Univeros\Polaris\Event\MemberRolesChanged;
use Univeros\Polaris\Event\MemberStatusChanged;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Event\MfaFactorRemoved;
use Univeros\Polaris\Event\MfaRecoveryRegenerated;
use Univeros\Polaris\Event\MfaRecoveryUsed;
use Univeros\Polaris\Event\MfaStepUpCompleted;
use Univeros\Polaris\Event\MfaVerified;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Event\OrganizationCreated;
use Univeros\Polaris\Event\OrganizationDeleted;
use Univeros\Polaris\Event\OtpChallengeSent;
use Univeros\Polaris\Event\OtpVerifyFailed;
use Univeros\Polaris\Event\PasswordChanged;
use Univeros\Polaris\Event\PasswordResetRequested;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\SessionsRevoked;
use Univeros\Polaris\Event\TokenRefreshed;
use Univeros\Polaris\Event\UserDeleted;
use Univeros\Polaris\Event\UserDisabled;
use Univeros\Polaris\Event\UserEmailVerified;
use Univeros\Polaris\Event\UserEnabled;
use Univeros\Polaris\Event\UserLocked;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Event\UserLoginFailed;
use Univeros\Polaris\Event\UserRegistered;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * PSR-14 listener persisting every Polaris domain event to the append-only `auth_audit_log`
 * (`docs/auth/events.md`). Subscribe it to the host's event dispatcher for each (or all) of the
 * `Univeros\Polaris\Event\*` classes.
 *
 * Each event maps to a **whitelist** of identifiers: the actor, the org context, the client IP
 * when the event carries one, and a small metadata blob of event-specific ids. Secrets never
 * reach a row by construction — the sensitive fields (verification/invite/reset tokens) are
 * simply not part of any mapping, so a new field on an event cannot leak without an explicit
 * change here. Unrecognized events are ignored.
 *
 * **Fail-open:** an audit write must never break the user-facing operation it observes — the
 * domain transaction has already committed when events fire. A failed insert is logged (PSR-3)
 * and swallowed; hosts that need guaranteed audit delivery should alert on that log channel.
 *
 * **Unit-of-work contract:** Polaris services dispatch events only *after* flushing their own
 * work (`docs/auth/events.md`), so this listener's flush on the shared unit of work only ever
 * writes the audit row it just persisted. A listener subscribed to events dispatched mid-cycle
 * (with unflushed entities pending) would flush those too — keep that invariant when adding
 * dispatch sites.
 */
final class AuditLogListener
{
    public function __construct(
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly ClockInterface $clock,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function __invoke(object $event): void
    {
        $record = match (true) {
            $event instanceof UserRegistered => [UserRegistered::NAME, $event->userId, null, null, ['email' => $event->email]],
            $event instanceof UserEmailVerified => [UserEmailVerified::NAME, $event->userId, null, null, ['email' => $event->email]],
            $event instanceof UserLoggedIn => [UserLoggedIn::NAME, $event->userId, null, $event->ip, ['session_id' => $event->sessionId]],
            $event instanceof UserLoginFailed => [UserLoginFailed::NAME, $event->userId, null, $event->ip, []],
            $event instanceof UserLocked => [UserLocked::NAME, $event->userId, null, $event->ip, []],
            $event instanceof PasswordChanged => [PasswordChanged::NAME, $event->userId, null, null, ['method' => $event->method]],
            $event instanceof PasswordResetRequested => [PasswordResetRequested::NAME, $event->userId, null, null, ['email' => $event->email]],
            $event instanceof UserDisabled => [UserDisabled::NAME, $event->actorUserId, null, null, ['user_id' => $event->userId]],
            $event instanceof UserEnabled => [UserEnabled::NAME, $event->actorUserId, null, null, ['user_id' => $event->userId]],
            $event instanceof UserDeleted => [UserDeleted::NAME, $event->actorUserId, null, null, ['user_id' => $event->userId]],
            $event instanceof TokenRefreshed => [TokenRefreshed::NAME, $event->userId, null, null, ['family_id' => $event->familyId]],
            $event instanceof RefreshReuseDetected => [RefreshReuseDetected::NAME, $event->userId, null, $event->ip, ['family_id' => $event->familyId]],
            $event instanceof SessionsRevoked => [SessionsRevoked::NAME, $event->userId, null, $event->ip, []],
            $event instanceof MfaEnrolled => [MfaEnrolled::NAME, $event->userId, null, null, ['factor_id' => $event->factorId]],
            $event instanceof MfaFactorRemoved => [MfaFactorRemoved::NAME, $event->userId, null, null, ['factor_id' => $event->factorId]],
            $event instanceof MfaVerified => [MfaVerified::NAME, $event->userId, null, null, ['factor_id' => $event->factorId]],
            $event instanceof MfaVerifyFailed => [MfaVerifyFailed::NAME, $event->userId, null, null, []],
            $event instanceof MfaStepUpCompleted => [MfaStepUpCompleted::NAME, $event->userId, null, null, ['session_id' => $event->sessionId]],
            $event instanceof MfaRecoveryRegenerated => [MfaRecoveryRegenerated::NAME, $event->userId, null, null, []],
            $event instanceof MfaRecoveryUsed => [MfaRecoveryUsed::NAME, $event->userId, null, null, ['remaining' => $event->remaining]],
            $event instanceof OtpChallengeSent => [OtpChallengeSent::NAME, $event->userId, null, null, ['factor_id' => $event->factorId, 'channel' => $event->channel]],
            $event instanceof OtpVerifyFailed => [OtpVerifyFailed::NAME, $event->userId, null, null, ['factor_id' => $event->factorId]],
            $event instanceof OrganizationCreated => [OrganizationCreated::NAME, $event->ownerUserId, $event->organizationId, null, ['slug' => $event->slug]],
            $event instanceof OrganizationDeleted => [OrganizationDeleted::NAME, $event->actorUserId, $event->organizationId, null, []],
            $event instanceof MemberInvited => [MemberInvited::NAME, $event->invitedBy, $event->organizationId, null, ['email' => $event->email]],
            $event instanceof MemberJoined => [MemberJoined::NAME, $event->userId, $event->organizationId, null, ['email' => $event->email]],
            $event instanceof MemberRolesChanged => [MemberRolesChanged::NAME, $event->actorUserId, $event->organizationId, null, ['user_id' => $event->userId, 'role_slugs' => $event->roleSlugs]],
            $event instanceof MemberStatusChanged => [MemberStatusChanged::NAME, $event->actorUserId, $event->organizationId, null, ['user_id' => $event->userId, 'status' => $event->status]],
            $event instanceof MemberRemoved => [MemberRemoved::NAME, $event->actorUserId, $event->organizationId, null, ['user_id' => $event->userId]],
            default => null,
        };

        if ($record === null) {
            return;
        }

        [$name, $actorUserId, $organizationId, $ip, $metadata] = $record;

        $entry = new AuditLogEntry();
        $entry->id = Uuid::v7()->toRfc4122();
        $entry->event = $name;
        $entry->actorUserId = $actorUserId;
        $entry->organizationId = $organizationId;
        $entry->ip = $ip;
        $entry->metadata = $this->encode($metadata);
        $entry->createdAt = $this->clock->now();

        try {
            $this->unitOfWork->persist($entry);
            $this->unitOfWork->flush();
        } catch (Throwable $exception) {
            $this->logger->error('Audit log write failed for {event}: {reason}', [
                'event' => $name,
                'reason' => $exception->getMessage(),
                'exception' => $exception,
            ]);
        }
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function encode(array $metadata): string
    {
        try {
            return json_encode($metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return '{}';
        }
    }
}
