<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Rule\RequestPathRule;
use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Security\Contracts\EncrypterInterface;
use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Http\Middleware\StepUpMiddleware;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;
use Univeros\Polaris\Mfa\MfaConfirmation;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\CountingRequestHandler;
use Univeros\Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;

use function preg_quote;

final class StepUpMiddlewareTest extends TestCase
{
    private const string NOW = '2026-06-09 12:00:00';
    private const int MAX_AGE = 300;

    private CountingRequestHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new CountingRequestHandler();
    }

    public function testANonSensitiveRoutePassesThrough(): void
    {
        $response = $this->middleware(hasFactor: true)
            ->process($this->authedRequest('/auth/me', authTimeAgo: 9999), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(1, $this->handler->calls);
    }

    public function testAUserWithoutAConfirmedFactorPassesThroughEvenWhenStale(): void
    {
        $response = $this->middleware(hasFactor: false)
            ->process($this->authedRequest('/auth/password/change', authTimeAgo: 9999), $this->handler);

        self::assertSame(200, $response->getStatusCode(), 'step-up does not apply without MFA');
        self::assertSame(1, $this->handler->calls);
    }

    public function testRecentAuthPassesThrough(): void
    {
        $response = $this->middleware(hasFactor: true)
            ->process($this->authedRequest('/auth/password/change', authTimeAgo: 100), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(1, $this->handler->calls);
    }

    public function testStaleAuthIsRejectedWithStepUpRequired(): void
    {
        $response = $this->middleware(hasFactor: true)
            ->process($this->authedRequest('/auth/password/change', authTimeAgo: 600), $this->handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('step_up_required', (string) $response->getBody());
        self::assertStringContainsString('step_up_required', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame(0, $this->handler->calls, 'the sensitive domain is never reached');
    }

    public function testAMissingAuthTimeIsTreatedAsStale(): void
    {
        $response = $this->middleware(hasFactor: true)
            ->process($this->authedRequest('/auth/password/change', authTimeAgo: null), $this->handler);

        self::assertSame(401, $response->getStatusCode());
    }

    public function testAnUnauthenticatedRequestPassesThrough(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/auth/password/change');

        $response = $this->middleware(hasFactor: true)->process($request, $this->handler);

        self::assertSame(200, $response->getStatusCode(), 'the access-token middleware owns this 401');
        self::assertSame(1, $this->handler->calls);
    }

    private function middleware(bool $hasFactor): StepUpMiddleware
    {
        return new StepUpMiddleware(
            new RequestPathRule(['path' => [preg_quote('/auth/password/change', '@')]]),
            $this->verifier($hasFactor),
            AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test', 'step_up' => ['max_age' => self::MAX_AGE]]),
            FrozenClock::at(self::NOW),
            new ResponseFactory(),
        );
    }

    private function verifier(bool $hasFactor): MfaChallengeVerifier
    {
        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('findBy')->willReturn($hasFactor ? [$this->confirmedFactor()] : []);

        $clock = FrozenClock::at(self::NOW);
        $uow = new RecordingUnitOfWork();
        $pepper = new Pepper('app-key-for-tests');
        $recovery = new RecoveryCodeService(new InMemoryRecoveryCodeRepository($uow), $uow, $pepper, $clock, new RecordingEventDispatcher());
        $confirmation = new MfaConfirmation($factors, $recovery, $uow, $clock, new RecordingEventDispatcher());
        $totp = new MfaTotpService(
            $factors,
            $this->createStub(TotpProviderInterface::class),
            $this->createStub(EncrypterInterface::class),
            $this->createStub(QrCodeRendererInterface::class),
            $confirmation,
            $uow,
            $clock,
        );
        $otp = new OtpService(
            $this->createStub(RepositoryInterface::class),
            $this->createStub(SmsSenderInterface::class),
            $this->createStub(OtpMailerInterface::class),
            $pepper,
            OtpConfig::fromArray([]),
            $uow,
            $clock,
            new RecordingEventDispatcher(),
        );

        return new MfaChallengeVerifier($factors, $totp, $otp, $recovery);
    }

    private function confirmedFactor(): MfaFactor
    {
        $now = new DateTimeImmutable(self::NOW);
        $factor = new MfaFactor();
        $factor->id = 'f-1';
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_TOTP;
        $factor->confirmedAt = $now;
        $factor->createdAt = $now;
        $factor->updatedAt = $now;

        return $factor;
    }

    private function authedRequest(string $path, ?int $authTimeAgo): ServerRequestInterface
    {
        $now = (new DateTimeImmutable(self::NOW))->getTimestamp();
        $token = $this->createStub(TokenInterface::class);
        $token->method('getMetadata')->willReturnMap([
            ['sub', 'user-1'],
            ['auth_time', $authTimeAgo === null ? null : $now - $authTimeAgo],
        ]);

        return (new ServerRequestFactory())->createServerRequest('POST', $path)
            ->withAttribute(TokenInterface::TOKEN_KEY, $token);
    }
}
