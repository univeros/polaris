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
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\UserLocked;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Event\UserLoginFailed;
use Univeros\Polaris\Exception\AccountDisabledException;
use Univeros\Polaris\Exception\EmailNotVerifiedException;
use Univeros\Polaris\Exception\InvalidCredentialsException;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\IssuedTokens;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\TokenService;

/**
 * Password login (no-MFA path): verifies credentials in constant time, enforces account
 * status / lockout / email-verification, and issues an access + refresh token pair.
 *
 * Anti-enumeration: a verify always runs — against a cached dummy hash when the user is
 * missing or passwordless — so the dominant Argon2id cost is equalized regardless of
 * whether the account exists. Unknown user, wrong password, and a locked account all
 * surface identically as {@see InvalidCredentialsException}. (A known-user failure still
 * writes the lockout counter, a small residual timing delta versus the unknown-user path;
 * the per-endpoint login rate limiting added in #15 is the compensating control.)
 *
 * Lockout is **windowed** (`auth.lockout` config): `max_attempts` failures within a rolling
 * `window` lock the account for `lock_duration`, after which it auto-unlocks. The window is
 * anchored on {@see User::$failedLoginAt}; failures spaced further apart than the window decay
 * (the streak resets) rather than accumulating forever, so an attacker cannot trip a lock with
 * a slow drip of guesses, and a legitimate user's occasional typos never compound into a lock.
 *
 * See `docs/auth/flows.md` §3 and `docs/auth/security.md` §6. The MFA gate and richer device
 * capture arrive in later phases; this issues tokens directly once credentials and account
 * state check out.
 */
final class LoginService
{
    // Hashed only for timing parity (never stored/compared); a fixed value is fine —
    // only the algorithm and cost matter for equalizing the verify duration.
    private const string DUMMY_SECRET = 'polaris-login-timing-parity-placeholder';

    private ?string $dummyHash = null;

    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly PasswordHasherInterface $hasher,
        private readonly TokenService $tokens,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly AuthConfig $config,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * @throws InvalidCredentialsException unknown user, wrong password, or locked account
     * @throws AccountDisabledException    correct password but the account is disabled
     * @throws EmailNotVerifiedException   correct password but the email is unverified
     */
    public function login(string $email, #[SensitiveParameter] string $password, ClientContext $client): LoginResult
    {
        $now = $this->clock->now();
        $user = $this->users->findOneBy(['email' => EmailNormalizer::normalize($email)]);
        $hash = $user instanceof User ? (string) $user->passwordHash : '';
        $locked = $user instanceof User && $user->lockedUntil !== null && $user->lockedUntil > $now;

        // Always run a verify (real or dummy) so timing does not leak account existence.
        $verified = $this->hasher->verify($password, $hash !== '' ? $hash : $this->dummyHash());

        if (!$user instanceof User || $hash === '' || !$verified) {
            // Record the failure only for an active, not-currently-locked account: skipping a live
            // lock avoids re-extending it on every attempt (a DoS), and skipping a DISABLED account
            // keeps the lockout lifecycle (which can flip LOCKED back to ACTIVE on expiry) from ever
            // re-enabling an account an admin disabled.
            if ($user instanceof User && !$locked && $user->status !== User::STATUS_DISABLED) {
                $this->recordFailure($user, $now, $client);
            }

            throw new InvalidCredentialsException('Invalid email or password.');
        }

        // A live lock is reported as a generic credential failure (no lock disclosure).
        if ($locked) {
            throw new InvalidCredentialsException('Invalid email or password.');
        }

        if ($user->status === User::STATUS_DISABLED) {
            throw new AccountDisabledException('This account is disabled.');
        }

        if ($this->config->requireVerifiedEmail && $user->emailVerifiedAt === null) {
            throw new EmailNotVerifiedException('Email address is not verified.');
        }

        $user->failedLoginCount = 0;
        $user->failedLoginAt = null;
        $user->lockedUntil = null;
        if ($user->status === User::STATUS_LOCKED) {
            $user->status = User::STATUS_ACTIVE;
        }
        if ($this->hasher->needsRehash($hash)) {
            $user->passwordHash = $this->hasher->hash($password);
        }
        $user->lastLoginAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);

        $tokens = $this->issueTokens($user, $now->getTimestamp(), $client);

        $this->events->dispatch(new UserLoggedIn($user->id, $tokens->sessionId, $client->ip));

        return new LoginResult($user->id, $user->email, $user->emailVerifiedAt !== null, $tokens);
    }

    private function issueTokens(User $user, int $authTime, ClientContext $client): IssuedTokens
    {
        $principal = new SessionPrincipal(
            userId: $user->id,
            emailVerified: $user->emailVerifiedAt !== null,
            amr: ['pwd'],
            authTime: $authTime,
        );

        // TokenService::issue flushes, committing the persisted user (last login / rehash) too.
        return $this->tokens->issue($principal, $client);
    }

    private function recordFailure(User $user, DateTimeImmutable $now, ClientContext $client): void
    {
        // Start a fresh failure window when the prior streak is stale — an expired lock, or a
        // last failure older than the window — so only failures clustered within the window count
        // toward a lock. A live DISABLED status is preserved (a failed guess never re-enables it).
        if ($this->failureWindowExpired($user, $now)) {
            $user->failedLoginCount = 0;
            $user->lockedUntil = null;
            if ($user->status === User::STATUS_LOCKED) {
                $user->status = User::STATUS_ACTIVE;
            }
        }

        ++$user->failedLoginCount;
        $user->failedLoginAt = $now;

        $locked = false;
        if ($user->lockedUntil === null && $user->failedLoginCount >= $this->config->lockoutMaxAttempts) {
            $user->lockedUntil = $now->add(new DateInterval('PT' . $this->config->lockoutDuration . 'S'));
            $user->status = User::STATUS_LOCKED;
            $locked = true;
        }

        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        $this->events->dispatch(new UserLoginFailed($user->id, $client->ip));
        if ($locked) {
            $this->events->dispatch(new UserLocked($user->id, $client->ip));
        }
    }

    /**
     * Whether the next failure should open a fresh window: true after an expired lock, or when the
     * most recent failure is older than `auth.lockout.window`. A first-ever failure
     * (`failedLoginAt === null`) continues the (empty) window rather than resetting.
     */
    private function failureWindowExpired(User $user, DateTimeImmutable $now): bool
    {
        if ($user->lockedUntil !== null && $user->lockedUntil <= $now) {
            return true;
        }

        if ($user->failedLoginAt === null) {
            return false;
        }

        return ($now->getTimestamp() - $user->failedLoginAt->getTimestamp()) > $this->config->lockoutWindow;
    }

    private function dummyHash(): string
    {
        return $this->dummyHash ??= $this->hasher->hash(self::DUMMY_SECRET);
    }
}
