<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Security\Contracts\EncrypterInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\MfaStepUpCompleted;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Identity\StepUpService;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;
use Univeros\Polaris\Mfa\MfaConfirmation;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Token\TokenService;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Univeros\Polaris\Tests\Support\InMemoryRefreshTokenRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingTokenGenerator;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;
use Univeros\Polaris\Tests\Support\StubSessionPrincipalResolver;

final class StepUpServiceTest extends TestCase
{
    private const string AT = '2026-06-09 12:00:00';

    private RecordingEventDispatcher $events;
    private RecordingTokenGenerator $accessTokens;
    private RecoveryCodeService $recovery;

    public function testRecoveryVerifyRefreshesTheSessionAndEmits(): void
    {
        $service = $this->service();
        $codes = $this->recovery->issue('user-1');

        $token = $service->verify('user-1', 'org-1', 'session-xyz', null, $codes[0]);

        self::assertNotSame('', $token);
        $claims = $this->accessTokens->claims[0];
        self::assertSame('user-1', $claims['sub']);
        self::assertSame('session-xyz', $claims['sid']);
        self::assertTrue($claims['mfa']);
        self::assertGreaterThan(0, $claims['auth_time'], 'a fresh auth_time is stamped');
        self::assertCount(1, $this->events->ofType(MfaStepUpCompleted::class));
        self::assertCount(0, $this->events->ofType(MfaVerifyFailed::class));
    }

    public function testAWrongCodeFailsWithoutRefreshing(): void
    {
        $service = $this->service();
        $this->recovery->issue('user-1');

        try {
            $service->verify('user-1', null, 'session-xyz', null, 'aaaaa-bbbbb');
            self::fail('a wrong recovery code must be rejected');
        } catch (InvalidOtpException) {
            // expected
        }

        self::assertSame([], $this->accessTokens->claims, 'no token is minted on failure');
        self::assertCount(1, $this->events->ofType(MfaVerifyFailed::class));
        self::assertCount(0, $this->events->ofType(MfaStepUpCompleted::class));
    }

    public function testAnUnconfirmedFactorIsRejected(): void
    {
        $service = $this->service(find: $this->factor(confirmed: false));

        try {
            $service->verify('user-1', null, 'session-xyz', 'f-1', '123456');
            self::fail('an unconfirmed factor must not satisfy step-up');
        } catch (MfaFactorNotFoundException) {
            // expected
        }

        self::assertCount(1, $this->events->ofType(MfaVerifyFailed::class));
        self::assertSame([], $this->accessTokens->claims);
    }

    private function service(?MfaFactor $find = null): StepUpService
    {
        $clock = FrozenClock::at(self::AT);
        $this->events = new RecordingEventDispatcher();
        $this->accessTokens = new RecordingTokenGenerator();

        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('find')->willReturn($find);
        $factors->method('findBy')->willReturn([]);

        $uow = new RecordingUnitOfWork();
        $pepper = new Pepper('app-key-for-tests');
        $this->recovery = new RecoveryCodeService(
            new InMemoryRecoveryCodeRepository($uow),
            $uow,
            $pepper,
            $clock,
            new RecordingEventDispatcher(),
        );

        $confirmation = new MfaConfirmation($factors, $this->recovery, $uow, $clock, new RecordingEventDispatcher());
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
            new InMemoryCache(),
        );

        $refresh = new InMemoryRefreshTokenRepository();
        $this->seedSession($refresh, 'session-xyz');
        $tokens = new TokenService(
            $refresh,
            $refresh,
            $pepper,
            $this->accessTokens,
            new StubSessionPrincipalResolver(),
            AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test']),
            $clock,
            new RecordingEventDispatcher(),
        );

        return new StepUpService(
            new MfaChallengeVerifier($factors, $totp, $otp, $this->recovery),
            $tokens,
            $this->events,
        );
    }

    private function seedSession(InMemoryRefreshTokenRepository $refresh, string $sessionId): void
    {
        $now = new DateTimeImmutable(self::AT);
        $token = new RefreshToken();
        $token->id = 'rt-seed';
        $token->userId = 'user-1';
        $token->familyId = $sessionId;
        $token->tokenHash = 'seed-hash';
        $token->expiresAt = $now->modify('+1 day');
        $token->createdAt = $now;
        $refresh->persist($token);
        $refresh->flush();
    }

    private function factor(bool $confirmed = true): MfaFactor
    {
        $now = new DateTimeImmutable(self::AT);
        $factor = new MfaFactor();
        $factor->id = 'f-1';
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_TOTP;
        $factor->confirmedAt = $confirmed ? $now : null;
        $factor->createdAt = $now;
        $factor->updatedAt = $now;

        return $factor;
    }
}
