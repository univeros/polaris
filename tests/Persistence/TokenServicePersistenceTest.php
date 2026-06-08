<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Exception\RefreshTokenReuseException;
use Univeros\Polaris\Persistence\RefreshTokenRepository;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingTokenGenerator;
use Univeros\Polaris\Tests\Support\StubSessionPrincipalResolver;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\TokenService;

/**
 * Exercises {@see TokenService} rotation and reuse detection against a real database
 * driver: issuing, rotating, and replaying refresh tokens through the real
 * {@see RefreshTokenRepository} + Cycle unit of work, asserting the persisted row state.
 */
final class TokenServicePersistenceTest extends DatabaseTestCase
{
    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        parent::setUp();
        $this->events = new RecordingEventDispatcher();
    }

    private function service(): TokenService
    {
        return new TokenService(
            new RefreshTokenRepository($this->orm, $this->unitOfWork),
            $this->unitOfWork,
            new Pepper('persistence-test-app-key'),
            new RecordingTokenGenerator(),
            new StubSessionPrincipalResolver(),
            AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test']),
            FrozenClock::at('2026-06-07 12:00:00'),
            $this->events,
        );
    }

    public function testRotationAndReuseDetectionAgainstARealDriver(): void
    {
        $issued = $this->service()->issue(
            new SessionPrincipal(userId: '0197f0a0-0000-7000-8000-000000000001', organizationId: null),
            new ClientContext('198.51.100.4', 'Test/1.0'),
        );
        $this->unitOfWork->clear();

        // Rotation: the presented token is revoked (rotated) and a new one is issued.
        $rotated = $this->service()->refresh($issued->refreshToken, ClientContext::none());
        $this->unitOfWork->clear();

        $family = $this->refreshTokens()->findBy(['familyId' => $issued->sessionId]);
        self::assertCount(2, $this->toList($family));

        // Replaying the original (now-rotated) token revokes the whole family.
        try {
            $this->service()->refresh($issued->refreshToken, new ClientContext('203.0.113.5'));
            self::fail('Expected reuse detection.');
        } catch (RefreshTokenReuseException) {
            // expected
        }
        $this->unitOfWork->clear();

        foreach ($this->refreshTokens()->findBy(['familyId' => $issued->sessionId]) as $token) {
            self::assertInstanceOf(RefreshToken::class, $token);
            self::assertNotNull($token->revokedAt, 'every family token is revoked after reuse');
        }

        self::assertCount(1, $this->events->ofType(RefreshReuseDetected::class));
        // The rotated token can no longer be exchanged either.
        self::assertNotSame($issued->refreshToken, $rotated->refreshToken);
    }

    private function refreshTokens(): RefreshTokenRepository
    {
        return new RefreshTokenRepository($this->orm, $this->unitOfWork);
    }

    /**
     * @param iterable<RefreshToken> $tokens
     *
     * @return list<RefreshToken>
     */
    private function toList(iterable $tokens): array
    {
        $list = [];
        foreach ($tokens as $token) {
            $list[] = $token;
        }

        return $list;
    }
}
