<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Entity\PasswordReset;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\PasswordChanged;
use Univeros\Polaris\Event\PasswordResetRequested;
use Univeros\Polaris\Exception\AccountDisabledException;
use Univeros\Polaris\Exception\InvalidCredentialsException;
use Univeros\Polaris\Exception\InvalidPasswordException;
use Univeros\Polaris\Exception\InvalidResetTokenException;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\ClientContext;

use function base64_encode;
use function random_bytes;
use function rtrim;
use function strtr;

/**
 * Password reset (forgot/reset) and authenticated change.
 *
 * Changing a password — by reset or change — always invalidates other sessions, a core
 * account-takeover containment measure: a reset revokes *all* sessions, a change revokes
 * all but the caller's current one. Reset tokens are 256-bit CSPRNG secrets stored only as
 * a keyed HMAC ({@see \Univeros\Polaris\Security\Pepper}); the plaintext travels once on
 * {@see PasswordResetRequested} for the mailer.
 *
 * See `docs/auth/flows.md` §8. The OTP (email+code) reset style and breach check arrive in
 * later phases; this implements the link-token style with the min-length policy.
 */
final class PasswordResetService
{
    private const string PEPPER_CONTEXT = 'password_reset';
    private const int TTL_SECONDS = 3600; // 1h — shorter than email verification by design
    private const int SECRET_BYTES = 32;

    /**
     * @param RepositoryInterface<User>          $users
     * @param RepositoryInterface<PasswordReset> $resets
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly RepositoryInterface $resets,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly PasswordHasherInterface $hasher,
        private readonly PasswordPolicy $policy,
        private readonly Pepper $pepper,
        private readonly SessionService $sessions,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Request a reset. Always a generic success: a challenge is created (and the mailer
     * notified) only for a known, active account.
     *
     * Anti-enumeration is by the uniform response — the caller can't tell a known from an unknown
     * address. The known-active path does a little more work (a DB write + token HMAC) than the
     * early return for a missing/inactive account, a small residual timing delta; the forgot
     * endpoint's rate limit (added in #15) is the compensating control. Writing dummy challenge
     * rows for non-existent accounts to equalize timing would be worse than the delta, so we don't.
     */
    public function forgot(string $email, ClientContext $client): void
    {
        $user = $this->users->findOneBy(['email' => EmailNormalizer::normalize($email)]);
        if (!$user instanceof User || $user->status !== User::STATUS_ACTIVE) {
            return;
        }

        $now = $this->clock->now();

        // Supersede any outstanding reset challenges so only the freshest token is valid.
        $this->consumePending($user->id, $now);
        $token = $this->newToken();

        $reset = new PasswordReset();
        $reset->id = $this->uuid();
        $reset->userId = $user->id;
        $reset->email = $user->email;
        $reset->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $token);
        $reset->expiresAt = $now->add(new DateInterval('PT' . self::TTL_SECONDS . 'S'));
        $reset->ip = $client->ip;
        $reset->createdAt = $now;
        $this->unitOfWork->persist($reset);
        $this->unitOfWork->flush();

        $this->events->dispatch(new PasswordResetRequested($user->id, $user->email, $token));
    }

    /**
     * Reset a password from a token, then revoke every session.
     *
     * @throws InvalidPasswordException   the new password fails the policy
     * @throws InvalidResetTokenException the token is unknown, consumed, or expired
     */
    public function reset(#[SensitiveParameter] string $token, #[SensitiveParameter] string $newPassword, ClientContext $client): void
    {
        $this->enforcePolicy($newPassword);

        $now = $this->clock->now();
        $challenge = $this->resets->findOneBy(['tokenHash' => $this->pepper->hash(self::PEPPER_CONTEXT, $token)]);

        if (!$challenge instanceof PasswordReset || $challenge->consumedAt !== null || $challenge->expiresAt <= $now) {
            throw new InvalidResetTokenException('The reset token is invalid or expired.');
        }

        $user = $this->users->find($challenge->userId);
        // A disabled account cannot re-enable itself via a reset; a locked one recovers
        // (the lock is cleared below) since proving email control is a legitimate recovery.
        if (!$user instanceof User || $user->status === User::STATUS_DISABLED) {
            throw new InvalidResetTokenException('The reset token is invalid or expired.');
        }

        $user->passwordHash = $this->hasher->hash($newPassword);
        $user->failedLoginCount = 0;
        $user->failedLoginAt = null;
        $user->lockedUntil = null;
        if ($user->status === User::STATUS_LOCKED) {
            $user->status = User::STATUS_ACTIVE;
        }
        $user->updatedAt = $now;
        $challenge->consumedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();

        $this->sessions->revokeAll($user->id, RefreshToken::REASON_PASSWORD_CHANGE);
        $this->events->dispatch(new PasswordChanged($user->id, PasswordChanged::METHOD_RESET));
    }

    /**
     * Change a password while authenticated, keeping the caller's current session and
     * revoking the rest.
     *
     * @throws InvalidCredentialsException the current password is wrong
     * @throws InvalidPasswordException    the new password fails the policy
     */
    public function change(
        string $userId,
        #[SensitiveParameter] string $currentPassword,
        #[SensitiveParameter] string $newPassword,
        ?string $currentSessionId,
        ClientContext $client,
    ): void {
        $user = $this->users->find($userId);
        if (
            !$user instanceof User || $user->passwordHash === null
            || !$this->hasher->verify($currentPassword, $user->passwordHash)
        ) {
            throw new InvalidCredentialsException('The current password is incorrect.');
        }

        if ($user->status === User::STATUS_DISABLED) {
            throw new AccountDisabledException('This account is disabled.');
        }

        $this->enforcePolicy($newPassword);

        $now = $this->clock->now();
        $user->passwordHash = $this->hasher->hash($newPassword);
        // A credential rotation clears stale failure/lock state — the caller proved control via the
        // current password — mirroring the reset path so the two stay consistent.
        $user->failedLoginCount = 0;
        $user->failedLoginAt = null;
        $user->lockedUntil = null;
        if ($user->status === User::STATUS_LOCKED) {
            $user->status = User::STATUS_ACTIVE;
        }
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        $this->sessions->revokeAllExcept($user->id, $currentSessionId, RefreshToken::REASON_PASSWORD_CHANGE);
        $this->events->dispatch(new PasswordChanged($user->id, PasswordChanged::METHOD_CHANGE));
    }

    private function enforcePolicy(#[SensitiveParameter] string $password): void
    {
        $violations = $this->policy->validate($password);
        if ($violations !== []) {
            throw new InvalidPasswordException($violations);
        }
    }

    private function consumePending(string $userId, DateTimeImmutable $now): void
    {
        foreach ($this->resets->findBy(['userId' => $userId]) as $challenge) {
            if ($challenge->consumedAt === null) {
                $challenge->consumedAt = $now;
                $this->unitOfWork->persist($challenge);
            }
        }
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(self::SECRET_BYTES)), '+/', '-_'), '=');
    }

    private function uuid(): string
    {
        return Uuid::v7()->toRfc4122();
    }
}
