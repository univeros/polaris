<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\OrganizationSwitched;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\TokenRefreshed;
use Univeros\Polaris\Exception\InvalidGrantException;
use Univeros\Polaris\Exception\RefreshTokenReuseException;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\InMemoryRefreshTokenRepository;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingTokenGenerator;
use Univeros\Polaris\Tests\Support\StubSessionPrincipalResolver;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\TokenService;

use function array_filter;
use function array_values;

final class TokenServiceTest extends TestCase
{
    private InMemoryRefreshTokenRepository $store;
    private RecordingTokenGenerator $generator;
    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->store = new InMemoryRefreshTokenRepository();
        $this->generator = new RecordingTokenGenerator();
        $this->events = new RecordingEventDispatcher();
    }

    private function serviceAt(string $time, ?AuthConfig $config = null): TokenService
    {
        return new TokenService(
            $this->store,
            $this->store,
            new Pepper('test-application-key-0123456789ab'),
            $this->generator,
            new StubSessionPrincipalResolver(roles: ['member']),
            $config ?? AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test']),
            FrozenClock::at($time),
            $this->events,
        );
    }

    /**
     * @param array<string, mixed> $refreshToken
     */
    private function configWith(array $refreshToken): AuthConfig
    {
        return AuthConfig::fromArray([
            'issuer' => 'https://auth.polaris.test',
            'refresh_token' => $refreshToken,
        ]);
    }

    private function principal(): SessionPrincipal
    {
        return new SessionPrincipal(userId: 'user-1', organizationId: 'org-1', emailVerified: true);
    }

    public function testIssueCreatesARefreshFamilyAndBindsTheAccessToken(): void
    {
        $issued = $this->serviceAt('2026-06-07 12:00:00')->issue($this->principal(), ClientContext::none());

        self::assertNotSame('', $issued->refreshToken);
        self::assertSame(900, $issued->accessExpiresIn);

        // One unrevoked refresh token, in the returned family.
        $stored = $this->store->findOneBy(['familyId' => $issued->sessionId]);
        self::assertInstanceOf(RefreshToken::class, $stored);
        self::assertNull($stored->revokedAt);
        self::assertNull($stored->parentId);

        // The access token is bound to the session and subject.
        self::assertSame('user-1', $this->generator->claims[0]['sub']);
        self::assertSame($issued->sessionId, $this->generator->claims[0]['sid']);
        self::assertSame('org-1', $this->generator->claims[0]['org']);
    }

    public function testRefreshRotatesTheTokenWithinTheSameFamily(): void
    {
        $issued = $this->serviceAt('2026-06-07 12:00:00')->issue($this->principal(), ClientContext::none());

        $rotated = $this->serviceAt('2026-06-07 12:05:00')->refresh($issued->refreshToken, ClientContext::none());

        self::assertNotSame($issued->refreshToken, $rotated->refreshToken);
        self::assertSame($issued->sessionId, $rotated->sessionId);

        $family = $this->store->findBy(['familyId' => $issued->sessionId]);
        self::assertCount(2, $family);

        // The presented token is consumed (revoked=rotated); the new one is active with a parent link.
        $active = array_values(array_filter($family, static fn(RefreshToken $t): bool => $t->revokedAt === null));
        $revoked = array_values(array_filter($family, static fn(RefreshToken $t): bool => $t->revokedAt !== null));
        self::assertCount(1, $active);
        self::assertCount(1, $revoked);
        self::assertSame(RefreshToken::REASON_ROTATED, $revoked[0]->revokedReason);
        self::assertSame($revoked[0]->id, $active[0]->parentId);

        self::assertCount(1, $this->events->ofType(TokenRefreshed::class));

        // The refreshed access token re-resolves authorization context: the issue token
        // carried the principal's (empty) roles, the refreshed one carries the resolver's.
        self::assertSame([], $this->generator->claims[0]['roles']);
        self::assertSame(['member'], $this->generator->claims[1]['roles']);
    }

    public function testRefreshCarriesTheSessionsAuthContextForward(): void
    {
        $authTime = (new DateTimeImmutable('2026-06-07 12:00:00'))->getTimestamp();
        $principal = new SessionPrincipal(
            userId: 'user-1',
            organizationId: 'org-1',
            emailVerified: true,
            mfa: true,
            amr: ['pwd', 'otp'],
            authTime: $authTime,
        );
        $issued = $this->serviceAt('2026-06-07 12:00:00')->issue($principal, ClientContext::none());

        $rotated = $this->serviceAt('2026-06-07 12:05:00')->refresh($issued->refreshToken, ClientContext::none());
        $this->serviceAt('2026-06-07 12:10:00')->refresh($rotated->refreshToken, ClientContext::none());

        // The resolver supplies authorization context only; how the user authenticated is
        // restored from the session row (issue #97) — a refreshed token still reads mfa=true,
        // across any number of rotations.
        foreach ([1, 2] as $i) {
            self::assertTrue($this->generator->claims[$i]['mfa'], "rotation $i keeps mfa");
            self::assertSame(['pwd', 'otp'], $this->generator->claims[$i]['amr']);
            self::assertSame($authTime, $this->generator->claims[$i]['auth_time']);
        }
    }

    public function testStepUpUpgradesTheSessionsStoredAuthContext(): void
    {
        $service = $this->serviceAt('2026-06-07 12:00:00');
        $issued = $service->issue($this->principal(), ClientContext::none()); // mfa=false, amr=['pwd']
        $service->stepUp('user-1', 'org-1', $issued->sessionId);

        $this->serviceAt('2026-06-07 12:10:00')->refresh($issued->refreshToken, ClientContext::none());

        // claims[0]=issue, [1]=step-up, [2]=refresh: the step-up's strong-auth context outlives
        // the access token it minted, because it was persisted onto the session row.
        $claims = $this->generator->claims[2];
        self::assertTrue($claims['mfa'], 'a refresh after step-up keeps the strong-auth context');
        self::assertSame(['pwd', 'otp'], $claims['amr']);
        self::assertSame((new DateTimeImmutable('2026-06-07 12:00:00'))->getTimestamp(), $claims['auth_time']);
    }

    public function testRotationDisabledKeepsTheSameTokenValid(): void
    {
        $config = $this->configWith(['rotation' => false]);
        $issued = $this->serviceAt('2026-06-07 12:00:00', $config)->issue($this->principal(), ClientContext::none());

        $refreshed = $this->serviceAt('2026-06-07 12:05:00', $config)->refresh($issued->refreshToken, ClientContext::none());

        // Same refresh token, never revoked, no new family member.
        self::assertSame($issued->refreshToken, $refreshed->refreshToken);
        $family = $this->store->findBy(['familyId' => $issued->sessionId]);
        self::assertCount(1, $family);
        self::assertNull($family[0]->revokedAt);
        self::assertNotNull($family[0]->lastUsedAt);
    }

    public function testStepUpMintsAFreshAccessTokenForTheExistingSessionWithoutTouchingRefresh(): void
    {
        $service = $this->serviceAt('2026-06-07 12:00:00');
        $issued = $service->issue($this->principal(), ClientContext::none());

        $token = $service->stepUp('user-1', 'org-1', $issued->sessionId);

        self::assertNotSame('', $token);
        self::assertCount(1, $this->store->findBy([]), 'step-up adds no refresh token to the family');

        // claims[0] is the issue access token; claims[1] is the step-up one.
        $claims = $this->generator->claims[1];
        self::assertSame('user-1', $claims['sub']);
        self::assertSame($issued->sessionId, $claims['sid']);
        self::assertTrue($claims['mfa']);
        self::assertSame(['pwd', 'otp'], $claims['amr']);
        self::assertSame((new DateTimeImmutable('2026-06-07 12:00:00'))->getTimestamp(), $claims['auth_time']);
    }

    public function testSwitchOrganizationAnnouncesTheRescope(): void
    {
        $service = $this->serviceAt('2026-06-07 12:00:00');
        $issued = $service->issue($this->principal(), ClientContext::none()); // scoped to org-1

        $token = $service->switchOrganization('user-1', 'org-2', $issued->sessionId);

        self::assertNotSame('', $token);
        $switches = $this->events->ofType(OrganizationSwitched::class);
        self::assertCount(1, $switches);
        self::assertSame('user-1', $switches[0]->userId);
        self::assertSame('org-1', $switches[0]->fromOrganizationId);
        self::assertSame('org-2', $switches[0]->toOrganizationId);
    }

    public function testStepUpRejectsARevokedSession(): void
    {
        $service = $this->serviceAt('2026-06-07 12:00:00');
        $issued = $service->issue($this->principal(), ClientContext::none());
        $service->revokeFamily($issued->sessionId, RefreshToken::REASON_LOGOUT);

        // A still-valid access token must not re-mint itself after its session was logged out.
        $this->expectException(InvalidGrantException::class);
        $service->stepUp('user-1', 'org-1', $issued->sessionId);
    }

    public function testReuseDetectionDisabledRejectsWithoutRevokingTheFamily(): void
    {
        $config = $this->configWith(['reuse_detection' => false]);
        $issued = $this->serviceAt('2026-06-07 12:00:00', $config)->issue($this->principal(), ClientContext::none());
        $this->serviceAt('2026-06-07 12:05:00', $config)->refresh($issued->refreshToken, ClientContext::none());

        // Replaying the rotated token is rejected, but as a plain invalid grant — the
        // family is not revoked and no theft alert fires.
        try {
            $this->serviceAt('2026-06-07 12:06:00', $config)->refresh($issued->refreshToken, ClientContext::none());
            self::fail('Expected an invalid-grant exception.');
        } catch (RefreshTokenReuseException) {
            self::fail('Reuse detection was disabled; expected a plain invalid grant.');
        } catch (InvalidGrantException) {
            // expected
        }

        $active = array_values(array_filter(
            $this->store->findBy(['familyId' => $issued->sessionId]),
            static fn(RefreshToken $t): bool => $t->revokedAt === null,
        ));
        self::assertCount(1, $active, 'the rotated child is still active');
        self::assertCount(0, $this->events->ofType(RefreshReuseDetected::class));
    }

    public function testSlidingExtendsExpiryUpToTheMaxLifetimeCap(): void
    {
        $config = $this->configWith(['sliding' => true, 'ttl' => 100, 'max_lifetime' => 150]);
        $issued = $this->serviceAt('2026-06-07 12:00:00', $config)->issue($this->principal(), ClientContext::none());

        // 30s in: extend to now+ttl (12:02:10), below the cap (familyStart 12:00:00 + 150 = 12:02:30).
        $first = $this->serviceAt('2026-06-07 12:00:30', $config)->refresh($issued->refreshToken, ClientContext::none());
        self::assertEquals(new DateTimeImmutable('2026-06-07 12:02:10'), $first->refreshExpiresAt);

        // Later (but before the first rotation's 12:02:10 expiry): now+ttl (12:02:40) would
        // exceed the cap, so expiry is clamped to familyStart + max_lifetime (12:02:30).
        $second = $this->serviceAt('2026-06-07 12:01:00', $config)->refresh($first->refreshToken, ClientContext::none());
        self::assertEquals(new DateTimeImmutable('2026-06-07 12:02:30'), $second->refreshExpiresAt);
    }

    public function testReplayingARotatedTokenRevokesTheWholeFamilyAndAlerts(): void
    {
        $issued = $this->serviceAt('2026-06-07 12:00:00')->issue($this->principal(), ClientContext::none());
        $this->serviceAt('2026-06-07 12:05:00')->refresh($issued->refreshToken, ClientContext::none());

        // Replaying the now-rotated original token is treated as theft.
        try {
            $this->serviceAt('2026-06-07 12:06:00')->refresh($issued->refreshToken, new ClientContext('203.0.113.9', 'Replay/1.0'));
            self::fail('Expected a reuse exception.');
        } catch (RefreshTokenReuseException) {
            // expected
        }

        // Every token in the family is revoked (reuse_detected for the ones still active).
        foreach ($this->store->findBy(['familyId' => $issued->sessionId]) as $token) {
            self::assertNotNull($token->revokedAt, 'all family tokens revoked');
        }

        $alerts = $this->events->ofType(RefreshReuseDetected::class);
        self::assertCount(1, $alerts);
        self::assertSame('user-1', $alerts[0]->userId);
        self::assertSame($issued->sessionId, $alerts[0]->familyId);
        self::assertSame('203.0.113.9', $alerts[0]->ip);
        self::assertSame('Replay/1.0', $alerts[0]->userAgent);
    }

    public function testReuseExceptionIsAnInvalidGrant(): void
    {
        self::assertInstanceOf(InvalidGrantException::class, new RefreshTokenReuseException());
    }

    public function testRefreshRejectsAnUnknownToken(): void
    {
        $this->expectException(InvalidGrantException::class);
        $this->serviceAt('2026-06-07 12:00:00')->refresh('not-a-real-token', ClientContext::none());
    }

    public function testRefreshRejectsAnExpiredToken(): void
    {
        $issued = $this->serviceAt('2026-06-07 12:00:00')->issue($this->principal(), ClientContext::none());

        // Default refresh TTL is 30 days; 60 days later the token is expired.
        $this->expectException(InvalidGrantException::class);
        $this->serviceAt('2026-08-06 12:00:00')->refresh($issued->refreshToken, ClientContext::none());
    }

    public function testRotatedTokenHashIsStoredHashedNeverPlaintext(): void
    {
        $issued = $this->serviceAt('2026-06-07 12:00:00')->issue($this->principal(), ClientContext::none());

        $stored = $this->store->findOneBy(['familyId' => $issued->sessionId]);
        self::assertInstanceOf(RefreshToken::class, $stored);
        self::assertNotSame($issued->refreshToken, $stored->tokenHash);
        self::assertSame(64, \strlen($stored->tokenHash)); // HMAC-SHA256 hex
    }
}
