<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use OTPHP\TOTP;
use Psr\Http\Message\ResponseInterface;
use Univeros\Polaris\Event\MfaVerified;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Event\UserRegistered;

use function base64_decode;
use function end;
use function explode;
use function json_decode;
use function preg_match;
use function strtr;
use function time;

/**
 * End-to-end tests for the #23 login MFA gate: a confirmed factor turns `/auth/login` into a
 * challenge (`mfa_required` + a short-lived `mfa_token`), the gate routes complete the second step
 * via TOTP / SMS / recovery code, and the `mfa_token` is rejected on normal routes. Driven through
 * the real pipeline and live database.
 */
final class MfaLoginGateEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'gate@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string PHONE = '+14155550101';

    public function testLoginReturnsAnMfaChallengeOnceAFactorIsConfirmed(): void
    {
        $access = $this->registerVerifyLogin();
        $this->enrollConfirmTotp($access);
        $this->unitOfWork->clear();

        $data = $this->json($this->login())['data'];

        self::assertTrue($data['mfa_required']);
        self::assertNotSame('', $data['mfa_token']);
        self::assertArrayNotHasKey('access_token', $data, 'no session is opened until MFA completes');
        self::assertSame('totp', $data['factors'][0]['type']);
        self::assertTrue($data['factors'][0]['default']);
    }

    public function testTheMfaTokenIsRejectedOnANormalRoute(): void
    {
        $access = $this->registerVerifyLogin();
        $this->enrollConfirmTotp($access);
        $this->unitOfWork->clear();
        $mfaToken = (string) $this->json($this->login())['data']['mfa_token'];

        self::assertSame(401, $this->authedGet('/auth/me', $mfaToken)->getStatusCode());
    }

    public function testTotpVerifyCompletesLoginAndMintsARealSession(): void
    {
        $access = $this->registerVerifyLogin();
        $totp = $this->enrollConfirmTotp($access);
        $this->unitOfWork->clear();
        $challenge = $this->json($this->login())['data'];

        // Confirm consumed the current TOTP step, so log in with a next-step code: the replay fence
        // rejects a step at or before the last-used one, and a real user is a window later anyway.
        $response = $this->authedPostJson(
            '/auth/mfa/verify',
            ['factor_id' => $challenge['factors'][0]['id'], 'code' => $this->nextStepCode($totp['secret'])],
            (string) $challenge['mfa_token'],
        );
        self::assertSame(200, $response->getStatusCode());

        $data = $this->json($response)['data'];
        self::assertNotSame('', $data['access_token']);
        self::assertNotSame('', $data['refresh_token']);

        $claims = $this->payload((string) $data['access_token']);
        self::assertTrue($claims['mfa']);
        self::assertSame(['pwd', 'otp'], $claims['amr']);
        self::assertCount(1, $this->events->ofType(MfaVerified::class));

        // The freshly minted access token authenticates a normal route.
        self::assertSame(200, $this->authedGet('/auth/me', (string) $data['access_token'])->getStatusCode());
    }

    public function testAWrongCodeIsRejectedAndEmitsFailure(): void
    {
        $access = $this->registerVerifyLogin();
        $this->enrollConfirmTotp($access);
        $this->unitOfWork->clear();
        $challenge = $this->json($this->login())['data'];

        $response = $this->authedPostJson(
            '/auth/mfa/verify',
            ['factor_id' => $challenge['factors'][0]['id'], 'code' => '000000'],
            (string) $challenge['mfa_token'],
        );

        self::assertSame(422, $response->getStatusCode());
        self::assertCount(1, $this->events->ofType(MfaVerifyFailed::class));
    }

    public function testARecoveryCodeCompletesLogin(): void
    {
        $access = $this->registerVerifyLogin();
        $totp = $this->enrollConfirmTotp($access);
        $this->unitOfWork->clear();
        $challenge = $this->json($this->login())['data'];

        $response = $this->authedPostJson(
            '/auth/mfa/verify',
            ['type' => 'recovery', 'code' => (string) $totp['recovery_codes'][0]],
            (string) $challenge['mfa_token'],
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertNotSame('', $this->json($response)['data']['access_token']);
    }

    public function testSmsChallengeThenVerifyCompletesLogin(): void
    {
        $access = $this->registerVerifyLogin();
        $factorId = $this->enrollConfirmSms($access);
        $this->unitOfWork->clear();
        $challenge = $this->json($this->login())['data'];
        $mfaToken = (string) $challenge['mfa_token'];

        $sent = $this->authedPostJson('/auth/mfa/challenge', ['factor_id' => $factorId], $mfaToken);
        self::assertSame(200, $sent->getStatusCode());
        self::assertSame('+1 *** *** 0101', $this->json($sent)['data']['destination']);

        $response = $this->authedPostJson(
            '/auth/mfa/verify',
            ['factor_id' => $factorId, 'code' => $this->lastSmsCode()],
            $mfaToken,
        );
        self::assertSame(200, $response->getStatusCode());
        self::assertNotSame('', $this->json($response)['data']['access_token']);
    }

    public function testChallengingATotpFactorIsRejected(): void
    {
        $access = $this->registerVerifyLogin();
        $this->enrollConfirmTotp($access);
        $this->unitOfWork->clear();
        $challenge = $this->json($this->login())['data'];

        $response = $this->authedPostJson(
            '/auth/mfa/challenge',
            ['factor_id' => $challenge['factors'][0]['id']],
            (string) $challenge['mfa_token'],
        );

        self::assertSame(422, $response->getStatusCode(), 'TOTP takes its code from the app, not a sent challenge');
    }

    public function testTheGateRoutesRequireATicket(): void
    {
        self::assertSame(401, $this->postJson('/auth/mfa/verify', ['code' => '123456'])->getStatusCode());
        self::assertSame(401, $this->postJson('/auth/mfa/challenge', ['factor_id' => 'x'])->getStatusCode());
    }

    /**
     * @return array{factor_id: string, secret: string, recovery_codes: list<string>}
     */
    private function enrollConfirmTotp(string $access): array
    {
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $confirm = $this->json($this->authedPostJson(
            '/auth/mfa/totp/confirm',
            ['factor_id' => $enroll['factor_id'], 'code' => $this->currentCode((string) $enroll['secret'])],
            $access,
        ))['data'];

        return [
            'factor_id' => (string) $enroll['factor_id'],
            'secret' => (string) $enroll['secret'],
            'recovery_codes' => $confirm['recovery_codes'],
        ];
    }

    private function enrollConfirmSms(string $access): string
    {
        $enroll = $this->json($this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE], $access));
        $factorId = (string) $enroll['data']['factor_id'];

        $this->authedPostJson(
            '/auth/mfa/sms/confirm',
            ['factor_id' => $factorId, 'code' => $this->lastSmsCode()],
            $access,
        );

        return $factorId;
    }

    private function login(): ResponseInterface
    {
        return $this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
    }

    private function currentCode(string $secret): string
    {
        return $this->totp($secret)->now();
    }

    /** A code for the next 30s step, so it clears the replay fence the confirm step set. */
    private function nextStepCode(string $secret): string
    {
        return $this->totp($secret)->at(time() + 30);
    }

    private function totp(string $secret): TOTP
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');

        return $totp;
    }

    private function lastSmsCode(): string
    {
        $last = end($this->sms->sent);
        self::assertNotFalse($last);
        self::assertSame(1, preg_match('/\b(\d{6})\b/', $last['message'], $m));

        return $m[1];
    }

    /**
     * Decode a JWT's claim set (the middle segment) so the test can assert `mfa`/`amr`.
     *
     * @return array<string, mixed>
     */
    private function payload(string $jwt): array
    {
        $segment = explode('.', $jwt)[1] ?? '';
        /** @var array<string, mixed> $claims */
        $claims = (array) json_decode((string) base64_decode(strtr($segment, '-_', '+/'), true), true);

        return $claims;
    }

    private function registerVerifyLogin(): string
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

        $body = $this->json($this->login());

        return (string) ($body['data']['access_token'] ?? '');
    }
}
