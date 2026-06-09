<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Event\OtpChallengeSent;
use Univeros\Polaris\Event\OtpVerifyFailed;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\OtpCooldownException;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingOtpMailer;
use Univeros\Polaris\Tests\Support\RecordingSmsSender;
use Univeros\Polaris\Tests\Support\RecordingUnitOfWork;
use Univeros\Polaris\Token\ClientContext;

use function preg_match;

final class OtpServiceTest extends TestCase
{
    private const string INSTANT = '2026-06-08 12:00:00';
    private const string PEPPER_KEY = 'app-key-for-tests';

    public function testChallengeStoresAHashedCodeSendsSmsAndMasksTheDestination(): void
    {
        $sms = new RecordingSmsSender();
        $uow = new RecordingUnitOfWork();
        $pepper = new Pepper(self::PEPPER_KEY);
        $events = new RecordingEventDispatcher();

        $result = $this->service($uow, sms: $sms, pepper: $pepper, events: $events)
            ->challenge('user-1', $this->smsFactor(), OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext('203.0.113.7'));

        self::assertSame(OtpChallenge::CHANNEL_SMS, $result->channel);
        self::assertSame('+1 *** *** 0101', $result->maskedDestination);

        self::assertCount(1, $sms->sent);
        self::assertSame('+14155550101', $sms->sent[0]['to']);
        self::assertSame(1, preg_match('/\b(\d{6})\b/', $sms->sent[0]['message'], $m), 'message carries a 6-digit code');
        $code = $m[1];

        self::assertCount(1, $uow->persisted);
        $challenge = $uow->persisted[0];
        self::assertInstanceOf(OtpChallenge::class, $challenge);
        self::assertNotSame($code, $challenge->codeHash, 'plaintext code is never stored');
        self::assertSame($pepper->hash('otp', $code), $challenge->codeHash);

        $sent = $events->ofType(OtpChallengeSent::class);
        self::assertCount(1, $sent);
        self::assertSame(OtpChallenge::CHANNEL_SMS, $sent[0]->channel);
    }

    public function testChallengeRejectsATotpFactor(): void
    {
        $totp = new MfaFactor();
        $totp->id = 'factor-9';
        $totp->userId = 'user-1';
        $totp->type = MfaFactor::TYPE_TOTP;

        $this->expectException(InvalidOtpException::class);

        $this->service(new RecordingUnitOfWork())
            ->challenge('user-1', $totp, OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));
    }

    public function testChallengeRejectsAFactorWithoutADestination(): void
    {
        $sms = new MfaFactor();
        $sms->id = 'factor-9';
        $sms->userId = 'user-1';
        $sms->type = MfaFactor::TYPE_SMS; // phoneE164 left null

        $this->expectException(InvalidOtpException::class);

        $this->service(new RecordingUnitOfWork())
            ->challenge('user-1', $sms, OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));
    }

    public function testRejectsAnUnknownPurpose(): void
    {
        $this->expectException(InvalidOtpException::class);

        $this->service(new RecordingUnitOfWork())
            ->challenge('user-1', $this->smsFactor(), 'not-a-purpose', new ClientContext(null));
    }

    public function testChallengeSendsEmailForAnEmailFactor(): void
    {
        $mailer = new RecordingOtpMailer();

        $result = $this->service(new RecordingUnitOfWork(), mailer: $mailer)
            ->challenge('user-1', $this->emailFactor(), OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));

        self::assertSame(OtpChallenge::CHANNEL_EMAIL, $result->channel);
        self::assertSame('a***@example.com', $result->maskedDestination);
        self::assertCount(1, $mailer->sent);
        self::assertSame('ada@example.com', $mailer->sent[0]['to']);
        self::assertArrayHasKey('code', $mailer->sent[0]['context']);
    }

    public function testChallengeWithinTheCooldownIsRejected(): void
    {
        $recent = $this->challenge(createdAt: new DateTimeImmutable(self::INSTANT)); // 0s ago < 30s cooldown

        $this->expectException(OtpCooldownException::class);

        $this->service(new RecordingUnitOfWork(), pending: [$recent])
            ->challenge('user-1', $this->smsFactor(), OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));
    }

    public function testChallengeSupersedesAnOlderPendingChallenge(): void
    {
        $old = $this->challenge(createdAt: new DateTimeImmutable('2026-06-08 11:00:00')); // 1h ago > cooldown

        $this->service(new RecordingUnitOfWork(), pending: [$old])
            ->challenge('user-1', $this->smsFactor(), OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));

        self::assertNotNull($old->consumedAt, 'the older pending challenge is superseded');
    }

    public function testVerifySucceedsAndConsumesTheChallenge(): void
    {
        $challenge = $this->challenge(code: '123456');

        $this->service(new RecordingUnitOfWork(), pending: [$challenge])
            ->verify('user-1', 'factor-1', '123456', OtpChallenge::PURPOSE_LOGIN_MFA);

        self::assertNotNull($challenge->consumedAt);
    }

    public function testVerifyOfAConsumedChallengeIsRejected(): void
    {
        $challenge = $this->challenge(code: '123456');
        $challenge->consumedAt = new DateTimeImmutable(self::INSTANT);

        $this->expectException(InvalidOtpException::class);

        $this->service(new RecordingUnitOfWork(), pending: [$challenge])
            ->verify('user-1', 'factor-1', '123456', OtpChallenge::PURPOSE_LOGIN_MFA);
    }

    public function testVerifyWithAWrongCodeIncrementsAttempts(): void
    {
        $challenge = $this->challenge(code: '123456');
        $events = new RecordingEventDispatcher();

        try {
            $this->service(new RecordingUnitOfWork(), pending: [$challenge], events: $events)
                ->verify('user-1', 'factor-1', '000000', OtpChallenge::PURPOSE_LOGIN_MFA);
            self::fail('expected InvalidOtpException');
        } catch (InvalidOtpException) {
            self::assertSame(1, $challenge->attempts);
            self::assertNull($challenge->consumedAt);
            self::assertCount(1, $events->ofType(OtpVerifyFailed::class));
        }
    }

    public function testVerifyIsRejectedOnceAttemptsAreExhausted(): void
    {
        $challenge = $this->challenge(code: '123456');
        $challenge->attempts = $challenge->maxAttempts;

        $this->expectException(InvalidOtpException::class);

        // Even the correct code is rejected once the attempt budget is spent.
        $this->service(new RecordingUnitOfWork(), pending: [$challenge])
            ->verify('user-1', 'factor-1', '123456', OtpChallenge::PURPOSE_LOGIN_MFA);
    }

    public function testVerifyOfAnExpiredChallengeIsRejected(): void
    {
        $challenge = $this->challenge(code: '123456');
        $challenge->expiresAt = new DateTimeImmutable('2026-06-08 11:00:00'); // past

        $this->expectException(InvalidOtpException::class);

        $this->service(new RecordingUnitOfWork(), pending: [$challenge])
            ->verify('user-1', 'factor-1', '123456', OtpChallenge::PURPOSE_LOGIN_MFA);
    }

    public function testSendQuotaThrottlesRepeatedSendsToADestination(): void
    {
        // The empty challenge stub means the resend cooldown never trips, isolating the send quota
        // (sendMax defaults to 5). One service instance shares one cache across the calls.
        $service = $this->service(new RecordingUnitOfWork());
        for ($i = 0; $i < 5; ++$i) {
            $service->challenge('user-1', $this->smsFactor(), OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));
        }

        $this->expectException(OtpCooldownException::class);
        $service->challenge('user-1', $this->smsFactor(), OtpChallenge::PURPOSE_LOGIN_MFA, new ClientContext(null));
    }

    /**
     * @param list<OtpChallenge> $pending
     */
    private function service(
        RecordingUnitOfWork $uow,
        array $pending = [],
        ?RecordingSmsSender $sms = null,
        ?RecordingOtpMailer $mailer = null,
        ?Pepper $pepper = null,
        ?RecordingEventDispatcher $events = null,
    ): OtpService {
        $challenges = $this->createStub(RepositoryInterface::class);
        $challenges->method('findBy')->willReturn($pending);

        return new OtpService(
            $challenges,
            $sms ?? new RecordingSmsSender(),
            $mailer ?? new RecordingOtpMailer(),
            $pepper ?? new Pepper(self::PEPPER_KEY),
            OtpConfig::fromArray([]),
            $uow,
            FrozenClock::at(self::INSTANT),
            $events ?? new RecordingEventDispatcher(),
            new InMemoryCache(),
        );
    }

    private function smsFactor(): MfaFactor
    {
        $factor = new MfaFactor();
        $factor->id = 'factor-1';
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_SMS;
        $factor->phoneE164 = '+14155550101';

        return $factor;
    }

    private function emailFactor(): MfaFactor
    {
        $factor = new MfaFactor();
        $factor->id = 'factor-2';
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_EMAIL;
        $factor->email = 'ada@example.com';

        return $factor;
    }

    private function challenge(string $code = '123456', ?DateTimeImmutable $createdAt = null): OtpChallenge
    {
        $now = new DateTimeImmutable(self::INSTANT);
        $challenge = new OtpChallenge();
        $challenge->id = 'challenge-1';
        $challenge->userId = 'user-1';
        $challenge->factorId = 'factor-1';
        $challenge->purpose = OtpChallenge::PURPOSE_LOGIN_MFA;
        $challenge->channel = OtpChallenge::CHANNEL_SMS;
        $challenge->codeHash = (new Pepper(self::PEPPER_KEY))->hash('otp', $code);
        $challenge->maxAttempts = OtpChallenge::DEFAULT_MAX_ATTEMPTS;
        $challenge->expiresAt = $now->modify('+5 minutes');
        $challenge->createdAt = $createdAt ?? $now;

        return $challenge;
    }
}
