<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\PasswordChanged;
use Univeros\Polaris\Event\PasswordResetRequested;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Persistence\UserRepository;

/**
 * End-to-end tests for password reset/change and `GET /auth/me`, driven through the real
 * pipeline and the live database.
 */
final class PasswordEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string NEW_PASSWORD = 'an entirely different passphrase';

    public function testForgotIsGenericAndNotifiesAKnownUser(): void
    {
        $this->register();

        self::assertSame(202, $this->postJson('/auth/password/forgot', ['email' => self::EMAIL])->getStatusCode());
        self::assertCount(1, $this->events->ofType(PasswordResetRequested::class));
    }

    public function testForgotIsGenericForAnUnknownEmail(): void
    {
        self::assertSame(202, $this->postJson('/auth/password/forgot', ['email' => 'nobody@example.com'])->getStatusCode());
        self::assertCount(0, $this->events->ofType(PasswordResetRequested::class));
    }

    public function testResetChangesThePasswordAndRevokesEverySession(): void
    {
        $this->register();
        $session = $this->login();
        $token = $this->requestReset();

        self::assertSame(200, $this->postJson('/auth/password/reset', ['token' => $token, 'new_password' => self::NEW_PASSWORD])->getStatusCode());
        self::assertNotEmpty($this->events->ofType(PasswordChanged::class));

        $this->unitOfWork->clear();
        // Every prior session is revoked, the new password works, the old one does not.
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $session['refresh']])->getStatusCode());
        self::assertSame(200, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::NEW_PASSWORD])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testResetRejectsAShortPasswordAndABadToken(): void
    {
        $this->register();
        $token = $this->requestReset();

        self::assertSame(422, $this->postJson('/auth/password/reset', ['token' => $token, 'new_password' => 'short'])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/password/reset', ['token' => 'not-a-token', 'new_password' => self::NEW_PASSWORD])->getStatusCode());
    }

    public function testAResetTokenCannotBeReplayed(): void
    {
        $this->register();
        $token = $this->requestReset();

        self::assertSame(200, $this->postJson('/auth/password/reset', ['token' => $token, 'new_password' => self::NEW_PASSWORD])->getStatusCode());
        $this->unitOfWork->clear();
        // The consumed token is rejected on a second use.
        self::assertSame(401, $this->postJson('/auth/password/reset', ['token' => $token, 'new_password' => 'yet another passphrase'])->getStatusCode());
    }

    public function testForgotIsGenericForADisabledUser(): void
    {
        $this->register();
        $this->setStatus(User::STATUS_DISABLED);

        self::assertSame(202, $this->postJson('/auth/password/forgot', ['email' => self::EMAIL])->getStatusCode());
        self::assertCount(0, $this->events->ofType(PasswordResetRequested::class));
    }

    public function testChangeKeepsTheCurrentSessionAndRevokesTheRest(): void
    {
        $this->register();
        $current = $this->login();
        $other = $this->login();

        $response = $this->authedPostJson(
            '/auth/password/change',
            ['current_password' => self::PASSWORD, 'new_password' => self::NEW_PASSWORD],
            $current['access'],
        );
        self::assertSame(200, $response->getStatusCode());

        $this->unitOfWork->clear();
        self::assertSame(200, $this->postJson('/auth/token/refresh', ['refresh_token' => $current['refresh']])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => $other['refresh']])->getStatusCode());
        self::assertSame(200, $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::NEW_PASSWORD])->getStatusCode());
    }

    public function testChangeRejectsAWrongCurrentPasswordAndAWeakNewOne(): void
    {
        $this->register();
        $session = $this->login();

        self::assertSame(403, $this->authedPostJson(
            '/auth/password/change',
            ['current_password' => 'wrong-password', 'new_password' => self::NEW_PASSWORD],
            $session['access'],
        )->getStatusCode());

        self::assertSame(422, $this->authedPostJson(
            '/auth/password/change',
            ['current_password' => self::PASSWORD, 'new_password' => 'short'],
            $session['access'],
        )->getStatusCode());
    }

    public function testChangeRequiresAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/auth/password/change', [
            'current_password' => self::PASSWORD,
            'new_password' => self::NEW_PASSWORD,
        ])->getStatusCode());
    }

    public function testMeReturnsTheIdentity(): void
    {
        $this->register();
        $session = $this->login();

        $response = $this->authedGet('/auth/me', $session['access']);
        self::assertSame(200, $response->getStatusCode());

        $body = $this->json($response);
        self::assertIsArray($body['data']);
        $data = $body['data'];
        self::assertSame(self::EMAIL, $data['email']);
        self::assertTrue($data['email_verified']);
        self::assertIsArray($data['orgs']);
        self::assertIsArray($data['roles']);
    }

    public function testMeRequiresAuthentication(): void
    {
        self::assertSame(401, $this->get('/auth/me')->getStatusCode());
    }

    private function register(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();
    }

    private function requestReset(): string
    {
        $this->postJson('/auth/password/forgot', ['email' => self::EMAIL]);

        return $this->events->ofType(PasswordResetRequested::class)[0]->resetToken;
    }

    private function setStatus(string $status): void
    {
        $users = new UserRepository($this->orm, $this->unitOfWork);
        $user = $users->findOneBy(['email' => self::EMAIL]);
        self::assertInstanceOf(User::class, $user);

        $user->status = $status;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();
    }

    /**
     * @return array{access: string, refresh: string}
     */
    private function login(): array
    {
        $body = $this->json($this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]));
        self::assertIsArray($body['data']);
        $data = $body['data'];

        return [
            'access' => (string) ($data['access_token'] ?? ''),
            'refresh' => (string) ($data['refresh_token'] ?? ''),
        ];
    }
}
