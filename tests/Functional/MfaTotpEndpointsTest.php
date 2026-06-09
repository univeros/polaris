<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use OTPHP\TOTP;
use Psr\Http\Message\ResponseInterface;
use Univeros\Polaris\Event\MfaEnrolled;
use Univeros\Polaris\Event\UserRegistered;

/**
 * End-to-end tests for TOTP enrollment + confirmation, driven through the real pipeline (the routes
 * are protected by the #15 auth middleware) and the live database.
 */
final class MfaTotpEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    public function testEnrollReturnsSecretUriAndQr(): void
    {
        $access = $this->registerVerifyLogin();

        $data = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];

        self::assertIsArray($data);
        self::assertNotSame('', $data['factor_id']);
        self::assertNotSame('', $data['secret']);
        self::assertStringStartsWith('otpauth://totp/', $data['otpauth_uri']);
        self::assertStringContainsString('<svg', $data['qr_svg']);
    }

    public function testConfirmWithAValidCodeIssuesRecoveryCodesOnce(): void
    {
        $access = $this->registerVerifyLogin();
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];

        $response = $this->confirm($enroll['factor_id'], $this->currentCode($enroll['secret']), $access);
        self::assertSame(200, $response->getStatusCode());

        $data = $this->json($response)['data'];
        self::assertSame('confirmed', $data['status']);
        self::assertCount(10, $data['recovery_codes']);
        self::assertCount(1, $this->events->ofType(MfaEnrolled::class));
    }

    public function testConfirmRejectsAWrongCodeAndAReplayedCode(): void
    {
        $access = $this->registerVerifyLogin();
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];

        // A wrong code is rejected; the factor stays unconfirmed.
        self::assertSame(422, $this->confirm($enroll['factor_id'], '000000', $access)->getStatusCode());

        $code = $this->currentCode($enroll['secret']);
        self::assertSame(200, $this->confirm($enroll['factor_id'], $code, $access)->getStatusCode());

        // Replaying the same code (still within its window) is rejected.
        $this->unitOfWork->clear();
        self::assertSame(422, $this->confirm($enroll['factor_id'], $code, $access)->getStatusCode());
    }

    public function testASecondFactorConfirmIssuesNoNewRecoveryCodes(): void
    {
        $access = $this->registerVerifyLogin();

        $first = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $this->confirm($first['factor_id'], $this->currentCode($first['secret']), $access);
        $this->unitOfWork->clear();

        $second = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $data = $this->json($this->confirm($second['factor_id'], $this->currentCode($second['secret']), $access))['data'];

        self::assertSame('confirmed', $data['status']);
        self::assertArrayNotHasKey('recovery_codes', $data, 'recovery codes are issued only for the first factor');
    }

    public function testEnrollAndConfirmRequireAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/auth/mfa/totp/enroll', [])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/mfa/totp/confirm', ['factor_id' => 'x', 'code' => '123456'])->getStatusCode());
    }

    private function confirm(string $factorId, string $code, string $access): ResponseInterface
    {
        return $this->authedPostJson('/auth/mfa/totp/confirm', ['factor_id' => $factorId, 'code' => $code], $access);
    }

    private function currentCode(string $secret): string
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');

        return $totp->now();
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
