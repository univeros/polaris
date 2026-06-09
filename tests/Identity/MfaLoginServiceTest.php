<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Identity;

use Altair\Http\Contracts\TokenParserInterface;
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
use Univeros\Polaris\Event\MfaVerified;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Identity\MfaLoginService;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;
use Univeros\Polaris\Mfa\MfaConfirmation;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Token\TokenService;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Univeros\Polaris\Tests\Support\InMemoryRefreshTokenRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingTokenGenerator;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;
use Univeros\Polaris\Tests\Support\StubSessionPrincipalResolver;

final class MfaLoginServiceTest extends TestCase
{
    private const string AT = '2026-06-09 12:00:00';

    private RecordingEventDispatcher $events;
    private RecordingTokenGenerator $accessTokens;
    private RecoveryCodeService $recovery;

    public function testConfirmedFactorsKeepsOnlyConfirmedOnes(): void
    {
        $confirmed = $this->factor('f-1', confirmed: true);
        $pending = $this->factor('f-2', confirmed: false);
        $service = $this->service(findBy: [$pending, $confirmed]);

        $result = $service->confirmedFactors('user-1');

        self::assertSame([$confirmed], $result);
    }

    public function testBeginChallengeMintsATicketAndMasksFactorViews(): void
    {
        $totp = $this->factor('f-totp', type: MfaFactor::TYPE_TOTP, confirmed: true);
        $totp->label = 'Authenticator';
        $totp->isDefault = true;
        $sms = $this->factor('f-sms', type: MfaFactor::TYPE_SMS, confirmed: true);
        $sms->phoneE164 = '+14155550123';
        $service = $this->service();

        $result = $service->beginChallenge('user-1', [$totp, $sms]);

        self::assertSame('user-1', $result->userId);
        self::assertNotSame('', $result->mfaToken);
        self::assertSame(
            ['id' => 'f-totp', 'type' => 'totp', 'default' => true, 'label' => 'Authenticator'],
            $result->factors[0]->toArray(),
            'a TOTP factor carries no destination',
        );
        self::assertSame(
            ['id' => 'f-sms', 'type' => 'sms', 'default' => false, 'destination' => '+1 *** *** 0123'],
            $result->factors[1]->toArray(),
            'an sms factor exposes only a masked destination',
        );
    }

    public function testVerifyWithARecoveryCodeMintsTheSessionAndEmits(): void
    {
        $service = $this->service();
        $codes = $this->recovery->issue('user-1');

        $tokens = $service->verify('user-1', null, $codes[0], ClientContext::none());

        self::assertNotSame('', $tokens->accessToken);
        $claims = $this->accessTokens->claims[0];
        self::assertTrue($claims['mfa']);
        self::assertSame(['pwd', 'otp'], $claims['amr']);
        self::assertGreaterThan(0, $claims['auth_time'], 'a fresh auth_time is stamped');
        self::assertCount(1, $this->events->ofType(MfaVerified::class));
        self::assertCount(1, $this->events->ofType(UserLoggedIn::class));
        self::assertCount(0, $this->events->ofType(MfaVerifyFailed::class));
    }

    public function testVerifyWithAWrongRecoveryCodeFailsAndEmitsNoSession(): void
    {
        $service = $this->service();
        $this->recovery->issue('user-1');

        try {
            $service->verify('user-1', null, 'aaaaa-bbbbb', ClientContext::none());
            self::fail('a wrong recovery code must be rejected');
        } catch (InvalidOtpException) {
            // expected
        }

        self::assertSame([], $this->accessTokens->claims, 'no token is minted on failure');
        self::assertCount(1, $this->events->ofType(MfaVerifyFailed::class));
        self::assertCount(0, $this->events->ofType(MfaVerified::class));
    }

    public function testVerifyRejectsAnUnknownOrUnconfirmedFactor(): void
    {
        $unconfirmed = $this->factor('f-1', confirmed: false);
        $service = $this->service(find: $unconfirmed);

        try {
            $service->verify('user-1', 'f-1', '123456', ClientContext::none());
            self::fail('an unconfirmed factor must not satisfy the gate');
        } catch (MfaFactorNotFoundException) {
            // expected
        }

        self::assertCount(1, $this->events->ofType(MfaVerifyFailed::class));
        self::assertSame([], $this->accessTokens->claims);
    }

    /**
     * @param list<MfaFactor> $findBy what the factor repository returns for findBy(userId)
     */
    private function service(?MfaFactor $find = null, array $findBy = []): MfaLoginService
    {
        $clock = FrozenClock::at(self::AT);
        $this->events = new RecordingEventDispatcher();
        $this->accessTokens = new RecordingTokenGenerator();

        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('find')->willReturn($find);
        $factors->method('findBy')->willReturn($findBy);

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

        $tickets = new MfaLoginTokenService(new RecordingTokenGenerator(), $this->createStub(TokenParserInterface::class));

        return new MfaLoginService(
            new MfaChallengeVerifier($factors, $totp, $otp, $this->recovery),
            $tickets,
            $tokens,
            new StubSessionPrincipalResolver(),
            $clock,
            $this->events,
        );
    }

    private function factor(string $id, string $type = MfaFactor::TYPE_TOTP, bool $confirmed = true): MfaFactor
    {
        $now = new DateTimeImmutable(self::AT);
        $factor = new MfaFactor();
        $factor->id = $id;
        $factor->userId = 'user-1';
        $factor->type = $type;
        $factor->confirmedAt = $confirmed ? $now : null;
        $factor->createdAt = $now;
        $factor->updatedAt = $now;

        return $factor;
    }
}
