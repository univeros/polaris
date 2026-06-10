<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use InvalidArgumentException;
use LogicException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Entity\EmailVerification;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Entity\PasswordReset;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\UserDeleted;
use Univeros\Polaris\Event\UserDisabled;
use Univeros\Polaris\Event\UserEnabled;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\UserNotFoundException;
use Univeros\Polaris\Security\Pepper;

use function in_array;
use function mb_strlen;
use function str_ends_with;
use function trim;

use const DATE_ATOM;

/**
 * Users administration (`docs/auth/api-reference.md` §5): read/update a profile (self, or admin
 * with `users.read`/`users.manage`), disable/enable an account (admin only), and delete —
 * **anonymize** — an account (self or admin).
 *
 * The actor's authority is re-resolved from the database (`users.*` is admin-scoped: held only by
 * `superadmin` by default). Disabling revokes every session (reason `admin`) and blocks login via
 * the status check in the login flow. Deletion keeps the row as a tombstone for referential/audit
 * integrity: the email is replaced with its keyed hash at `@deleted.invalid`, the profile and
 * credentials are nulled, MFA factors (which carry phone numbers) are removed, and all sessions
 * are revoked (`docs/auth/security.md` §9, right to erasure).
 */
final class UserAdminService
{
    private const string ERASURE_PEPPER_CONTEXT = 'user_erasure';
    private const string TOMBSTONE_EMAIL_SUFFIX = '@deleted.invalid';
    private const int DISPLAY_NAME_MAX = 120;

    /**
     * @param RepositoryInterface<User>              $users
     * @param RepositoryInterface<MfaFactor>         $mfaFactors
     * @param RepositoryInterface<OtpChallenge>      $otpChallenges
     * @param RepositoryInterface<EmailVerification> $emailVerifications
     * @param RepositoryInterface<PasswordReset>     $passwordResets
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly RepositoryInterface $mfaFactors,
        private readonly RepositoryInterface $otpChallenges,
        private readonly RepositoryInterface $emailVerifications,
        private readonly RepositoryInterface $passwordResets,
        private readonly PermissionResolver $resolver,
        private readonly SessionService $sessions,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly Pepper $pepper,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Read a user: self, or an actor holding `users.read`.
     *
     * @return array<string, mixed>
     *
     * @throws AuthorizationException not self and no `users.read`
     * @throws UserNotFoundException
     */
    public function read(string $actorUserId, ?string $actorOrganizationId, string $userId): array
    {
        $this->assertSelfOrPermission($actorUserId, $actorOrganizationId, $userId, PermissionCatalog::USERS_READ);

        return $this->shape($this->userOrFail($userId));
    }

    /**
     * Update a user's profile (currently the display name): self, or an actor holding `users.manage`.
     *
     * @return array<string, mixed> the updated user
     *
     * @throws AuthorizationException   not self and no `users.manage`
     * @throws UserNotFoundException
     * @throws InvalidArgumentException display name too long
     */
    public function updateProfile(string $actorUserId, ?string $actorOrganizationId, string $userId, ?string $displayName): array
    {
        $this->assertSelfOrPermission($actorUserId, $actorOrganizationId, $userId, PermissionCatalog::USERS_MANAGE);
        $user = $this->userOrFail($userId);

        if ($displayName !== null) {
            $displayName = trim($displayName);
            if (mb_strlen($displayName) > self::DISPLAY_NAME_MAX) {
                throw new InvalidArgumentException('The display name must be 120 characters or fewer.');
            }
            $user->displayName = $displayName === '' ? null : $displayName;
        }

        $user->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        return $this->shape($user);
    }

    /**
     * Disable an account: every session is revoked and the login flow rejects it until re-enabled.
     * The caller's `users.manage` is enforced by the AuthorizationMiddleware; self-disablement is
     * refused so an operator cannot lock themselves out mid-session.
     *
     * @throws LogicException        disabling yourself
     * @throws UserNotFoundException
     */
    public function disable(string $actorUserId, string $userId): void
    {
        if ($actorUserId === $userId) {
            throw new LogicException('You cannot disable your own account.');
        }
        $user = $this->userOrFail($userId);

        $becameDisabled = $user->status !== User::STATUS_DISABLED;
        if ($becameDisabled) {
            $user->status = User::STATUS_DISABLED;
            $user->updatedAt = $this->clock->now();
            $this->unitOfWork->persist($user);
            $this->unitOfWork->flush();
        }

        // Revoke on every call (idempotent), so a disable whose revocation step failed mid-way
        // is recoverable by retrying; the event fires only on the actual transition.
        $this->sessions->revokeAll($userId, RefreshToken::REASON_ADMIN);

        if ($becameDisabled) {
            $this->events->dispatch(new UserDisabled($userId, $actorUserId));
        }
    }

    /**
     * Re-enable a disabled (or locked) account and clear the lockout counters. An anonymized
     * tombstone is refused — it has no credentials and must never read as a live account.
     *
     * @throws UserNotFoundException
     * @throws LogicException        re-enabling an anonymized account
     */
    public function enable(string $actorUserId, string $userId): void
    {
        $user = $this->userOrFail($userId);
        if ($this->isTombstone($user)) {
            throw new LogicException('The account has been anonymized and cannot be re-enabled.');
        }

        $user->status = User::STATUS_ACTIVE;
        $user->failedLoginCount = 0;
        $user->failedLoginAt = null;
        $user->lockedUntil = null;
        $user->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        $this->events->dispatch(new UserEnabled($userId, $actorUserId));
    }

    /**
     * Delete (anonymize) an account: self, or an actor holding `users.manage`. The row remains as
     * a tombstone so audit/foreign references stay intact.
     *
     * @throws AuthorizationException not self and no `users.manage`
     * @throws UserNotFoundException
     */
    public function erase(string $actorUserId, ?string $actorOrganizationId, string $userId): void
    {
        $this->assertSelfOrPermission($actorUserId, $actorOrganizationId, $userId, PermissionCatalog::USERS_MANAGE);
        $user = $this->userOrFail($userId);

        $user->email = $this->pepper->hash(self::ERASURE_PEPPER_CONTEXT, $user->email) . self::TOMBSTONE_EMAIL_SUFFIX;
        $user->displayName = null;
        $user->passwordHash = null;
        $user->emailVerifiedAt = null;
        $user->status = User::STATUS_DISABLED;
        $user->mfaEnforced = false;
        $user->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($user);

        // Scrub the transient rows that carry plaintext PII: MFA factors (phone numbers, TOTP
        // secrets), OTP challenges (destination phone/email), and email-verification /
        // password-reset challenges (plaintext email). Refresh-token rows keep their ip/user_agent
        // — they are revoked session records retained for theft-detection audit, per data-model
        // retention. The audit log itself references the user id, which survives as a tombstone.
        foreach ([$this->mfaFactors, $this->otpChallenges, $this->emailVerifications, $this->passwordResets] as $repository) {
            foreach ($repository->findBy(['userId' => $userId]) as $row) {
                $this->unitOfWork->remove($row);
            }
        }
        $this->unitOfWork->flush();

        $this->sessions->revokeAll($userId, RefreshToken::REASON_ADMIN);

        $this->events->dispatch(new UserDeleted($userId, $actorUserId));
    }

    /**
     * @throws AuthorizationException
     */
    private function assertSelfOrPermission(string $actorUserId, ?string $actorOrganizationId, string $userId, string $permission): void
    {
        if ($actorUserId === $userId) {
            return;
        }

        $authority = $this->resolver->resolve($actorUserId, $actorOrganizationId);
        if (!in_array($permission, $authority->scope, true)) {
            throw new AuthorizationException('You may only manage your own account.');
        }
    }

    private function isTombstone(User $user): bool
    {
        return $user->passwordHash === null && str_ends_with($user->email, self::TOMBSTONE_EMAIL_SUFFIX);
    }

    private function userOrFail(string $userId): User
    {
        $user = $this->users->find($userId);
        if (!$user instanceof User) {
            throw new UserNotFoundException('The user does not exist.');
        }

        return $user;
    }

    /**
     * @return array<string, mixed>
     */
    private function shape(User $user): array
    {
        return [
            'id' => $user->id,
            'email' => $user->email,
            'display_name' => $user->displayName,
            'status' => $user->status,
            'email_verified' => $user->emailVerifiedAt !== null,
            'mfa_enforced' => $user->mfaEnforced,
            'created_at' => $user->createdAt->format(DATE_ATOM),
            'last_login_at' => $user->lastLoginAt?->format(DATE_ATOM),
        ];
    }
}
