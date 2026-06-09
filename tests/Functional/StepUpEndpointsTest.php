<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use OTPHP\TOTP;
use Psr\Http\Message\ResponseInterface;
use Univeros\Polaris\Event\MfaStepUpCompleted;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\TokenService;

use function base64_decode;
use function explode;
use function json_decode;
use function strtr;
use function time;

/**
 * End-to-end tests for step-up re-authentication (#25): a sensitive route is rejected with
 * `401 step_up_required` when the session's `auth_time` is stale, and `POST /auth/mfa/step-up`
 * refreshes it so the retry succeeds. Driven through the real pipeline + Postgres.
 */
final class StepUpEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'stepup@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    public function testStalePasswordChangeIsRejectedThenAllowedAfterStepUp(): void
    {
        ['secret' => $secret, 'userId' => $userId, 'factorId' => $factorId] = $this->userWithTotp();
        $stale = $this->staleToken($userId);

        $blocked = $this->changePassword($stale);
        self::assertSame(401, $blocked->getStatusCode());
        self::assertStringContainsString('step_up_required', (string) $blocked->getBody());
        self::assertStringContainsString('step_up_required', $blocked->getHeaderLine('WWW-Authenticate'));

        $fresh = $this->stepUp($secret, $factorId, $stale);

        self::assertSame(200, $this->changePassword($fresh)->getStatusCode());
    }

    public function testRegenerateRecoveryCodesRequiresStepUp(): void
    {
        ['secret' => $secret, 'userId' => $userId, 'factorId' => $factorId] = $this->userWithTotp();
        $stale = $this->staleToken($userId);

        self::assertSame(401, $this->authedPostJson('/auth/mfa/recovery-codes/regenerate', [], $stale)->getStatusCode());

        $fresh = $this->stepUp($secret, $factorId, $stale);
        $regen = $this->authedPostJson('/auth/mfa/recovery-codes/regenerate', [], $fresh);

        self::assertSame(200, $regen->getStatusCode());
        self::assertCount(10, $this->json($regen)['data']['recovery_codes']);
    }

    public function testStepUpRejectsAWrongCode(): void
    {
        ['userId' => $userId, 'factorId' => $factorId] = $this->userWithTotp();
        $stale = $this->staleToken($userId);

        $response = $this->authedPostJson('/auth/mfa/step-up', ['factor_id' => $factorId, 'code' => '000000'], $stale);

        self::assertSame(422, $response->getStatusCode());
        self::assertCount(0, $this->events->ofType(MfaStepUpCompleted::class));
    }

    public function testStepUpChallengeRejectsATotpFactor(): void
    {
        ['userId' => $userId, 'factorId' => $factorId] = $this->userWithTotp();
        $stale = $this->staleToken($userId);

        $response = $this->authedPostJson('/auth/mfa/step-up/challenge', ['factor_id' => $factorId], $stale);

        self::assertSame(422, $response->getStatusCode(), 'TOTP takes its code from the app, not a sent challenge');
    }

    public function testAUserWithoutMfaCanChangePasswordWithoutStepUp(): void
    {
        // No factor enrolled → step-up does not apply even with a (synthetic) stale token.
        $access = $this->registerVerifyLogin();
        $stale = $this->staleToken($this->subjectOf($access));

        self::assertSame(200, $this->changePassword($stale)->getStatusCode());
    }

    /**
     * Register, verify, log in, and enrol+confirm a TOTP factor.
     *
     * @return array{secret: string, userId: string, factorId: string}
     */
    private function userWithTotp(): array
    {
        $access = $this->registerVerifyLogin();
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $this->authedPostJson(
            '/auth/mfa/totp/confirm',
            ['factor_id' => $enroll['factor_id'], 'code' => $this->currentCode((string) $enroll['secret'])],
            $access,
        );
        $this->unitOfWork->clear();

        return [
            'secret' => (string) $enroll['secret'],
            'userId' => $this->subjectOf($access),
            'factorId' => (string) $enroll['factor_id'],
        ];
    }

    /** Complete a step-up with a TOTP factor and return the refreshed access token. */
    private function stepUp(string $secret, string $factorId, string $accessToken): string
    {
        // A next-step code clears the replay fence the confirm step set (as in the login gate).
        $response = $this->authedPostJson(
            '/auth/mfa/step-up',
            ['factor_id' => $factorId, 'code' => $this->nextStepCode($secret)],
            $accessToken,
        );
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(1, $this->events->ofType(MfaStepUpCompleted::class));

        return (string) $this->json($response)['data']['access_token'];
    }

    private function changePassword(string $accessToken): ResponseInterface
    {
        return $this->authedPostJson(
            '/auth/password/change',
            ['current_password' => self::PASSWORD, 'new_password' => 'a different strong password'],
            $accessToken,
        );
    }

    /** A valid access token whose auth_time is far past the step-up window (but not itself expired). */
    private function staleToken(string $userId): string
    {
        $tokens = $this->container->get(TokenService::class);
        self::assertInstanceOf(TokenService::class, $tokens);
        $principal = new SessionPrincipal(
            userId: $userId,
            emailVerified: true,
            mfa: true,
            amr: ['pwd', 'otp'],
            authTime: time() - 100000,
        );

        return $tokens->issue($principal, ClientContext::none())->accessToken;
    }

    private function subjectOf(string $jwt): string
    {
        $segment = explode('.', $jwt)[1] ?? '';
        /** @var array<string, mixed> $claims */
        $claims = (array) json_decode((string) base64_decode(strtr($segment, '-_', '+/'), true), true);

        return (string) ($claims['sub'] ?? '');
    }

    private function currentCode(string $secret): string
    {
        return $this->totp($secret)->now();
    }

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
