<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\EmailVerification;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\UserEmailVerified;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Exception\InvalidVerificationTokenException;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\ClientContext;

use function base64_encode;
use function random_bytes;
use function rtrim;
use function strtr;

/**
 * Issues, confirms, and re-sends single-use email-verification tokens.
 *
 * A token is a 256-bit CSPRNG secret; only its keyed HMAC hash ({@see Pepper}) is stored
 * in `auth_email_verifications`, and the plaintext travels once on the {@see UserRegistered}
 * event for the mailer. Confirmation is idempotent (re-verifying an already-verified user
 * succeeds) and reveals nothing about why a bad token failed.
 *
 * See `docs/auth/flows.md` §2.
 */
final class EmailVerificationService
{
    private const string PEPPER_CONTEXT = 'email_verify';
    private const int TTL_SECONDS = 86400; // 24h
    private const int SECRET_BYTES = 32;

    /**
     * @param RepositoryInterface<User>              $users
     * @param RepositoryInterface<EmailVerification> $verifications
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly RepositoryInterface $verifications,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly Pepper $pepper,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Create a verification challenge for the user and schedule it for persistence (the
     * caller flushes). Returns the plaintext token to carry on the registration event.
     */
    public function issueChallenge(User $user, ClientContext $client): string
    {
        $now = $this->clock->now();
        $token = $this->newToken();

        $verification = new EmailVerification();
        $verification->id = $this->uuid();
        $verification->userId = $user->id;
        $verification->email = $user->email;
        $verification->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $token);
        $verification->expiresAt = $now->add(new DateInterval('PT' . self::TTL_SECONDS . 'S'));
        $verification->ip = $client->ip;
        $verification->createdAt = $now;

        $this->unitOfWork->persist($verification);

        return $token;
    }

    /**
     * Confirm an email address from its token. Idempotent for an already-verified user.
     *
     * @throws InvalidVerificationTokenException when the token is unknown, consumed, or expired
     */
    public function verify(string $token): void
    {
        $challenge = $this->verifications->findOneBy([
            'tokenHash' => $this->pepper->hash(self::PEPPER_CONTEXT, $token),
        ]);

        if (!$challenge instanceof EmailVerification) {
            throw new InvalidVerificationTokenException('The verification token is invalid.');
        }

        $user = $this->users->find($challenge->userId);
        if (!$user instanceof User) {
            throw new InvalidVerificationTokenException('The verification token is invalid.');
        }

        // Idempotency precedes the validity check on purpose: a user clicking the link
        // twice presents an already-consumed token the second time and must still get a
        // success, not an error. The presented token still had to match a real challenge.
        if ($user->emailVerifiedAt !== null) {
            return;
        }

        $now = $this->clock->now();
        if ($challenge->consumedAt !== null || $challenge->expiresAt <= $now) {
            throw new InvalidVerificationTokenException('The verification token has expired.');
        }

        $user->emailVerifiedAt = $now;
        $user->updatedAt = $now;
        $challenge->consumedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();

        $this->events->dispatch(new UserEmailVerified($user->id, $user->email));
    }

    /**
     * Re-issue a verification challenge. Always a no-op-looking success: it reissues only
     * for a known, still-unverified user, so the response is identical either way.
     */
    public function resend(string $email, ClientContext $client): void
    {
        $user = $this->users->findOneBy(['email' => EmailNormalizer::normalize($email)]);

        if (!$user instanceof User || $user->emailVerifiedAt !== null) {
            return;
        }

        // Supersede any outstanding challenges so only the freshly-issued token is valid.
        $this->consumePending($user->id);
        $token = $this->issueChallenge($user, $client);
        $this->unitOfWork->flush();

        $this->events->dispatch(new UserRegistered($user->id, $user->email, $token));
    }

    private function consumePending(string $userId): void
    {
        $now = $this->clock->now();
        foreach ($this->verifications->findBy(['userId' => $userId]) as $challenge) {
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
