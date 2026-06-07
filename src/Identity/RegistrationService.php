<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Exception\InvalidPasswordException;
use Univeros\Polaris\Token\ClientContext;

/**
 * Registers new users: validates the password policy, creates the (unverified) account
 * with an Argon2id hash, issues an email-verification challenge, and emits
 * {@see UserRegistered} for the mailer.
 *
 * Anti-enumeration: when the email already exists no account is created and no event is
 * emitted, but a dummy hash is still computed so the response time matches the
 * account-created path — the caller returns an identical generic `202` either way.
 *
 * See `docs/auth/flows.md` §1.
 */
final class RegistrationService
{
    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly EmailVerificationService $verifications,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly PasswordHasherInterface $hasher,
        private readonly PasswordPolicy $policy,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * @throws InvalidPasswordException when the password fails the policy
     */
    public function register(
        string $email,
        #[SensitiveParameter] string $password,
        ?string $displayName,
        ClientContext $client,
    ): void {
        $violations = $this->policy->validate($password);
        if ($violations !== []) {
            throw new InvalidPasswordException($violations);
        }

        $email = EmailNormalizer::normalize($email);

        if ($this->users->findOneBy(['email' => $email]) !== null) {
            // Equalize timing with the create path (Argon2id dominates), then stop.
            $this->hasher->hash($password);

            return;
        }

        $now = $this->clock->now();
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->passwordHash = $this->hasher->hash($password);
        $user->displayName = $displayName;
        $user->createdAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);

        $token = $this->verifications->issueChallenge($user, $client);
        $this->unitOfWork->flush();

        $this->events->dispatch(new UserRegistered($user->id, $user->email, $token));
    }
}
