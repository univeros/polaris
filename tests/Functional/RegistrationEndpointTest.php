<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\UserEmailVerified;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Persistence\UserRepository;

/**
 * End-to-end tests for the registration + email-verification endpoints, driven through
 * the real Action pipeline and the live database.
 */
final class RegistrationEndpointTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    public function testRegisterThenVerifyHappyPath(): void
    {
        $register = $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        self::assertSame(202, $register->getStatusCode());

        $registered = $this->events->ofType(UserRegistered::class);
        self::assertCount(1, $registered);
        $token = $registered[0]->verificationToken;

        $user = $this->users()->findOneBy(['email' => self::EMAIL]);
        self::assertInstanceOf(User::class, $user);
        self::assertNull($user->emailVerifiedAt, 'newly registered user is unverified');
        self::assertNotNull($user->passwordHash);

        $verify = $this->postJson('/auth/email/verify', ['token' => $token]);
        self::assertSame(200, $verify->getStatusCode());

        $this->unitOfWork->clear();
        $verified = $this->users()->findOneBy(['email' => self::EMAIL]);
        self::assertInstanceOf(User::class, $verified);
        self::assertNotNull($verified->emailVerifiedAt);
        self::assertCount(1, $this->events->ofType(UserEmailVerified::class));
    }

    public function testRegisterIsGenericAndDoesNotDuplicateAnExistingAccount(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $second = $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);

        // Identical generic response, and no second account/registration event.
        self::assertSame(202, $second->getStatusCode());
        self::assertCount(1, $this->events->ofType(UserRegistered::class));
    }

    public function testRegisterNormalizesTheEmail(): void
    {
        $this->postJson('/auth/register', ['email' => '  ADA@Example.com ', 'password' => self::PASSWORD]);

        self::assertInstanceOf(User::class, $this->users()->findOneBy(['email' => self::EMAIL]));
    }

    public function testRegisterRejectsAShortPassword(): void
    {
        $response = $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => 'short']);

        self::assertSame(422, $response->getStatusCode());
        self::assertArrayHasKey('errors', $this->json($response));
        self::assertCount(0, $this->events->ofType(UserRegistered::class));
    }

    public function testRegisterRequiresEmailAndPassword(): void
    {
        self::assertSame(422, $this->postJson('/auth/register', ['email' => self::EMAIL])->getStatusCode());
    }

    public function testVerifyRejectsAnUnknownToken(): void
    {
        self::assertSame(400, $this->postJson('/auth/email/verify', ['token' => 'not-a-real-token'])->getStatusCode());
    }

    public function testVerifyRequiresAToken(): void
    {
        self::assertSame(422, $this->postJson('/auth/email/verify', [])->getStatusCode());
    }

    public function testRejectsAnInvalidEmailFormat(): void
    {
        self::assertSame(422, $this->postJson('/auth/register', ['email' => 'not-an-email', 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testResendReissuesForAKnownUnverifiedUser(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $firstToken = $this->events->ofType(UserRegistered::class)[0]->verificationToken;

        $resend = $this->postJson('/auth/email/verify/resend', ['email' => self::EMAIL]);
        self::assertSame(202, $resend->getStatusCode());

        // A second user.registered carried a *new* token, and the original was superseded.
        $tokens = $this->events->ofType(UserRegistered::class);
        self::assertCount(2, $tokens);
        self::assertNotSame($firstToken, $tokens[1]->verificationToken);

        $this->unitOfWork->clear();
        self::assertSame(400, $this->postJson('/auth/email/verify', ['token' => $firstToken])->getStatusCode());
        self::assertSame(200, $this->postJson('/auth/email/verify', ['token' => $tokens[1]->verificationToken])->getStatusCode());
    }

    public function testResendRequiresAValidEmail(): void
    {
        self::assertSame(422, $this->postJson('/auth/email/verify/resend', ['email' => 'bogus'])->getStatusCode());
    }

    public function testVerifyIsIdempotent(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;

        self::assertSame(200, $this->postJson('/auth/email/verify', ['token' => $token])->getStatusCode());
        $this->unitOfWork->clear();
        // Re-verifying with the same token still succeeds (user already verified).
        self::assertSame(200, $this->postJson('/auth/email/verify', ['token' => $token])->getStatusCode());
    }

    public function testResendIsAlwaysGeneric(): void
    {
        // Unknown address: still a generic 202, and no challenge/event is created.
        $response = $this->postJson('/auth/email/verify/resend', ['email' => 'nobody@example.com']);

        self::assertSame(202, $response->getStatusCode());
        self::assertCount(0, $this->events->ofType(UserRegistered::class));
    }

    private function users(): UserRepository
    {
        return new UserRepository($this->orm, $this->unitOfWork);
    }
}
