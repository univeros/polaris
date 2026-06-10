<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Altair\Http\Contracts\TokenValidatorInterface;
use DateTimeImmutable;
use Laminas\Diactoros\ServerRequestFactory;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\UserLocked;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Persistence\UserRepository;

/**
 * End-to-end tests for `POST /auth/login`, driven through the real Action pipeline and
 * the live database: valid login issues a verifiable token pair; credential/lock failures
 * are a generic `401`; account-state failures are `403`.
 */
final class LoginEndpointTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    private function registerAndVerify(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();
    }

    public function testValidLoginIssuesAVerifiableTokenPair(): void
    {
        $this->registerAndVerify();

        $response = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        self::assertSame(200, $response->getStatusCode());

        $body = $this->json($response);
        self::assertIsArray($body['data']);
        $data = $body['data'];

        self::assertNotSame('', $data['access_token']);
        self::assertNotSame('', $data['refresh_token']);
        self::assertSame('Bearer', $data['token_type']);
        self::assertIsArray($data['user']);
        self::assertSame(self::EMAIL, $data['user']['email']);
        self::assertTrue($data['user']['email_verified']);

        self::assertCount(1, $this->events->ofType(UserLoggedIn::class));

        // The minted access token verifies against the module's own validator.
        $validator = $this->container->get(TokenValidatorInterface::class);
        self::assertInstanceOf(TokenValidatorInterface::class, $validator);
        self::assertTrue($validator->validate((string) $data['access_token']));
    }

    public function testLoginCarriesTheSanitizedUserAgentIntoTheEvent(): void
    {
        $this->registerAndVerify();

        $request = (new ServerRequestFactory())->createServerRequest('POST', '/auth/login')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('User-Agent', 'Browser/1.0 (Functional)')
            ->withParsedBody(['email' => self::EMAIL, 'password' => self::PASSWORD]);
        self::assertSame(200, $this->harness->handle($request)->getStatusCode());

        // The ClientContextMiddleware → ClientContext → event chain holds end to end (#90).
        $logins = $this->events->ofType(UserLoggedIn::class);
        self::assertCount(1, $logins);
        self::assertSame('Browser/1.0 (Functional)', $logins[0]->userAgent);
        self::assertSame(['pwd'], $logins[0]->amr);
    }

    public function testWrongPasswordIsAGeneric401(): void
    {
        $this->registerAndVerify();

        $response = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'not-the-password']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_credentials', $this->json($response)['error']);
    }

    public function testUnknownUserIsAGeneric401(): void
    {
        $response = $this->postJson('/auth/login', ['email' => 'nobody@example.com', 'password' => self::PASSWORD]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_credentials', $this->json($response)['error']);
    }

    public function testUnverifiedEmailIsForbidden(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $this->unitOfWork->clear();

        $response = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('email_unverified', $this->json($response)['error']);
    }

    public function testDisabledAccountIsForbidden(): void
    {
        $this->registerAndVerify();
        $this->disable(self::EMAIL);

        $response = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('account_disabled', $this->json($response)['error']);
    }

    public function testRequiresEmailAndPassword(): void
    {
        self::assertSame(422, $this->postJson('/auth/login', ['email' => self::EMAIL])->getStatusCode());
    }

    public function testSuccessfulLoginStampsLastLoginAndClearsFailures(): void
    {
        $this->registerAndVerify();
        // Two wrong attempts, then the correct one.
        $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);
        $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);

        self::assertSame(200, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD])->getStatusCode());

        $this->unitOfWork->clear();
        $user = $this->user(self::EMAIL);
        self::assertSame(0, $user->failedLoginCount, 'failure counter reset on success');
        self::assertNull($user->failedLoginAt, 'failure window anchor cleared on success');
        self::assertNotNull($user->lastLoginAt);
        self::assertNull($user->lockedUntil);
    }

    public function testRepeatedFailuresLockTheAccount(): void
    {
        $this->registerAndVerify();

        // Default lockout is 5 attempts.
        for ($attempt = 0; $attempt < 5; ++$attempt) {
            $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);
        }

        self::assertNotEmpty($this->events->ofType(UserLocked::class));

        // The correct password is now rejected with the same generic 401 while locked.
        $this->unitOfWork->clear();
        $response = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testLockAutoExpires(): void
    {
        $this->registerAndVerify();
        for ($attempt = 0; $attempt < 5; ++$attempt) {
            $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);
        }

        // Wind the lock into the past, simulating the lockout window having elapsed.
        $user = $this->user(self::EMAIL);
        self::assertNotNull($user->lockedUntil);
        $user->lockedUntil = new DateTimeImmutable('2000-01-01 00:00:00');
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();

        // The correct password now succeeds (auto-unlock) and clears the lock state.
        self::assertSame(200, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD])->getStatusCode());
        $this->unitOfWork->clear();
        $reloaded = $this->user(self::EMAIL);
        self::assertNull($reloaded->lockedUntil);
        self::assertSame(0, $reloaded->failedLoginCount);
        self::assertNull($reloaded->failedLoginAt);
    }

    public function testFailuresOutsideTheWindowDoNotAccumulateToALock(): void
    {
        $this->registerAndVerify();

        // Four failures, one shy of the default lock threshold (5).
        for ($attempt = 0; $attempt < 4; ++$attempt) {
            $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);
        }

        // Age the streak past the lockout window, so the next failure starts a fresh window
        // (mirrors how testLockAutoExpires winds lock state into the past).
        $user = $this->user(self::EMAIL);
        self::assertSame(4, $user->failedLoginCount);
        $user->failedLoginAt = new DateTimeImmutable('2000-01-01 00:00:00');
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();

        // A cumulative counter would lock on this fifth failure; the window instead resets it.
        $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong']);

        $this->unitOfWork->clear();
        $reloaded = $this->user(self::EMAIL);
        self::assertSame(1, $reloaded->failedLoginCount, 'the stale streak reset to a single fresh failure');
        self::assertNull($reloaded->lockedUntil, 'the account is not locked');

        // The correct password still logs in.
        self::assertSame(200, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testFailedLoginsAgainstADisabledAccountNeverReEnableIt(): void
    {
        $this->registerAndVerify();
        $this->disable(self::EMAIL);

        // Enough wrong-password attempts to lock an active account (default threshold 5).
        for ($attempt = 0; $attempt < 5; ++$attempt) {
            self::assertSame(401, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'wrong'])->getStatusCode());
        }

        $this->unitOfWork->clear();
        $user = $this->user(self::EMAIL);
        self::assertSame(User::STATUS_DISABLED, $user->status, 'a disabled account stays out of the lockout lifecycle');
        self::assertSame(0, $user->failedLoginCount);
        self::assertNull($user->lockedUntil);

        // The correct password still reports the account as disabled (403) — never re-enabled.
        self::assertSame(403, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testUnknownUserAndWrongPasswordAreIndistinguishable(): void
    {
        $this->registerAndVerify();

        $wrongPassword = $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => 'not-the-password']);
        $unknownUser = $this->postJson('/auth/login', ['email' => 'nobody@example.com', 'password' => self::PASSWORD]);

        // Same status and same error body — the caller cannot tell which account exists.
        self::assertSame(401, $wrongPassword->getStatusCode());
        self::assertSame($wrongPassword->getStatusCode(), $unknownUser->getStatusCode());
        self::assertSame('invalid_credentials', $this->json($wrongPassword)['error']);
        self::assertSame($this->json($wrongPassword)['error'], $this->json($unknownUser)['error']);
    }

    private function disable(string $email): void
    {
        $user = $this->user($email);
        $user->status = User::STATUS_DISABLED;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();
    }

    private function user(string $email): User
    {
        $user = (new UserRepository($this->orm, $this->unitOfWork))->findOneBy(['email' => $email]);
        self::assertInstanceOf(User::class, $user);

        return $user;
    }
}
