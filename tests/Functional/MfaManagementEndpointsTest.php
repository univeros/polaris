<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use OTPHP\TOTP;
use Psr\Http\Message\ResponseInterface;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\MfaFactorRemoved;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Persistence\UserRepository;

use function array_column;
use function array_slice;
use function base64_decode;
use function end;
use function explode;
use function json_decode;
use function preg_match;
use function strtr;

/**
 * End-to-end tests for MFA factor management + enforcement + OTP abuse controls (#26): list / relabel
 * / re-default / remove factors, the last-confirmed-factor removal block under enforcement, and the
 * per-destination/account send cap. Driven through the real pipeline + Postgres.
 */
final class MfaManagementEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'manage@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string PHONE = '+14155550101';

    public function testListShowsConfirmedAndPendingFactors(): void
    {
        $access = $this->registerVerifyLogin();
        $this->enrollConfirmTotp($access);
        $this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE], $access); // pending

        $factors = $this->json($this->authedGet('/auth/mfa/factors', $access))['data']['factors'];

        self::assertCount(2, $factors);
        $byType = [];
        foreach ($factors as $factor) {
            $byType[$factor['type']] = $factor;
        }
        self::assertTrue($byType['totp']['confirmed']);
        self::assertFalse($byType['sms']['confirmed']);
        self::assertSame('+1 *** *** 0101', $byType['sms']['destination']);
    }

    public function testRelabelAndSetDefault(): void
    {
        $access = $this->registerVerifyLogin();
        $totp = $this->enrollConfirmTotp($access);                 // first factor → default
        $sms = $this->enrollConfirmSms($access);

        $patched = $this->json($this->authedPatch(
            "/auth/mfa/factors/$sms",
            ['label' => 'Personal phone', 'default' => true],
            $access,
        ))['data'];

        self::assertSame('Personal phone', $patched['label']);
        self::assertTrue($patched['default']);

        $factors = $this->json($this->authedGet('/auth/mfa/factors', $access))['data']['factors'];
        self::assertTrue($this->factorById($factors, $sms)['default']);
        self::assertFalse($this->factorById($factors, $totp)['default'], 'the previous default is cleared');
    }

    public function testDeleteRemovesAFactor(): void
    {
        $access = $this->registerVerifyLogin();
        $totp = $this->enrollConfirmTotp($access);
        $sms = $this->enrollConfirmSms($access);

        $response = $this->authedDelete("/auth/mfa/factors/$sms", $access);
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(1, $this->events->ofType(MfaFactorRemoved::class));

        $remaining = $this->json($this->authedGet('/auth/mfa/factors', $access))['data']['factors'];
        self::assertSame([$totp], array_column($remaining, 'id'));
    }

    public function testRemovingTheLastConfirmedFactorIsBlockedWhenEnforced(): void
    {
        $access = $this->registerVerifyLogin();
        $totp = $this->enrollConfirmTotp($access);
        $this->enforceMfa($this->subjectOf($access));

        $response = $this->authedDelete("/auth/mfa/factors/$totp", $access);

        self::assertSame(409, $response->getStatusCode());
        self::assertStringContainsString('last_factor_protected', (string) $response->getBody());
        self::assertCount(0, $this->events->ofType(MfaFactorRemoved::class));
    }

    public function testOtpSendBombingIsCapped(): void
    {
        $access = $this->registerVerifyLogin();

        // send_max defaults to 5 per destination/account per window; each enrol sends one code.
        $statuses = [];
        for ($i = 0; $i < 6; ++$i) {
            $statuses[] = $this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE], $access)->getStatusCode();
        }

        self::assertSame([200, 200, 200, 200, 200], array_slice($statuses, 0, 5));
        self::assertSame(429, $statuses[5], 'the sixth send to the destination is throttled');
    }

    private function enrollConfirmTotp(string $access): string
    {
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $this->authedPostJson(
            '/auth/mfa/totp/confirm',
            ['factor_id' => $enroll['factor_id'], 'code' => $this->currentTotpCode((string) $enroll['secret'])],
            $access,
        );
        $this->unitOfWork->clear();

        return (string) $enroll['factor_id'];
    }

    private function enrollConfirmSms(string $access): string
    {
        $enroll = $this->json($this->authedPostJson('/auth/mfa/sms/enroll', ['phone_e164' => self::PHONE], $access));
        $factorId = (string) $enroll['data']['factor_id'];
        $this->authedPostJson('/auth/mfa/sms/confirm', ['factor_id' => $factorId, 'code' => $this->lastSmsCode()], $access);
        $this->unitOfWork->clear();

        return $factorId;
    }

    private function enforceMfa(string $userId): void
    {
        $users = $this->container->get(UserRepository::class);
        self::assertInstanceOf(UserRepository::class, $users);
        $user = $users->find($userId);
        self::assertInstanceOf(User::class, $user);
        $user->mfaEnforced = true;
        $users->save($user);
        $this->unitOfWork->clear();
    }

    /**
     * @param list<array<string, mixed>> $factors
     *
     * @return array<string, mixed>
     */
    private function factorById(array $factors, string $id): array
    {
        foreach ($factors as $factor) {
            if (($factor['id'] ?? null) === $id) {
                return $factor;
            }
        }

        self::fail("Factor $id not found in the list.");
    }

    private function authedPatch(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('PATCH', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withParsedBody($body);

        return $this->harness->handle($request);
    }

    private function lastSmsCode(): string
    {
        $last = end($this->sms->sent);
        self::assertNotFalse($last);
        self::assertSame(1, preg_match('/\b(\d{6})\b/', $last['message'], $m));

        return $m[1];
    }

    private function currentTotpCode(string $secret): string
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');

        return $totp->now();
    }

    private function subjectOf(string $jwt): string
    {
        $segment = explode('.', $jwt)[1] ?? '';
        /** @var array<string, mixed> $claims */
        $claims = (array) json_decode((string) base64_decode(strtr($segment, '-_', '+/'), true), true);

        return (string) ($claims['sub'] ?? '');
    }

    private function registerVerifyLogin(): string
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

        $body = $this->json($this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]));

        return (string) ($body['data']['access_token'] ?? '');
    }
}
