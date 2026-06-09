<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Univeros\Polaris\Event\UserRegistered;

use function end;
use function preg_match;

/**
 * End-to-end tests for SMS + email factor enroll/confirm, driven through the real pipeline (the
 * routes are protected by the #15 auth middleware) and the live database. The recording senders
 * bound by {@see FunctionalTestCase} let the test read the delivered code.
 */
final class MfaSmsEmailEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string PHONE = '+14155550101';

    public function testSmsEnrollAndConfirmIssuesRecoveryCodes(): void
    {
        $access = $this->registerVerifyLogin();

        $enroll = $this->json($this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE], $access));
        self::assertSame('+1 *** *** 0101', $enroll['data']['destination']);
        $factorId = (string) $enroll['data']['factor_id'];

        $response = $this->authedPostJson(
            '/auth/mfa/sms/confirm',
            ['factor_id' => $factorId, 'code' => $this->lastSmsCode()],
            $access,
        );
        self::assertSame(200, $response->getStatusCode());

        $data = $this->json($response)['data'];
        self::assertSame('confirmed', $data['status']);
        self::assertCount(10, $data['recovery_codes']);
    }

    public function testSmsEnrollRejectsAnInvalidE164(): void
    {
        $access = $this->registerVerifyLogin();

        $response = $this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => '415-555-0101'], $access);

        self::assertSame(422, $response->getStatusCode());
    }

    public function testSmsConfirmRejectsAWrongCode(): void
    {
        $access = $this->registerVerifyLogin();
        $enroll = $this->json($this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE], $access));

        $response = $this->authedPostJson(
            '/auth/mfa/sms/confirm',
            ['factor_id' => (string) $enroll['data']['factor_id'], 'code' => '000000'],
            $access,
        );

        self::assertSame(422, $response->getStatusCode());
    }

    public function testEmailEnrollDefaultsToTheAccountEmailAndConfirms(): void
    {
        $access = $this->registerVerifyLogin();

        $response = $this->authedPostJson('/auth/mfa/email/enroll', [], $access);
        self::assertSame(200, $response->getStatusCode());
        $factorId = (string) $this->json($response)['data']['factor_id'];

        // No email supplied → the code goes to the account email.
        $lastEmail = end($this->mailer->sent);
        self::assertNotFalse($lastEmail);
        self::assertSame(self::EMAIL, $lastEmail['to']);

        $confirm = $this->authedPostJson(
            '/auth/mfa/email/confirm',
            ['factor_id' => $factorId, 'code' => (string) $lastEmail['context']['code']],
            $access,
        );
        self::assertSame(200, $confirm->getStatusCode());
    }

    public function testEnrollAndConfirmRequireAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/mfa/email/confirm', ['factor_id' => 'x', 'code' => '123456'])->getStatusCode());
    }

    private function lastSmsCode(): string
    {
        $last = end($this->sms->sent);
        self::assertNotFalse($last);
        self::assertSame(1, preg_match('/\b(\d{6})\b/', $last['message'], $m));

        return $m[1];
    }

    private function registerVerifyLogin(): string
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

        $body = $this->json($this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]));
        self::assertIsArray($body['data']);

        return (string) ($body['data']['access_token'] ?? '');
    }
}
