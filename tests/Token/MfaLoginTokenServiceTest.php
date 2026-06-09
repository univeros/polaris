<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Altair\Http\Exception\InvalidTokenException;
use Altair\Http\Jwt\LcobucciTokenParser;
use Altair\Http\Support\TokenConfiguration;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Token\AccessTokenClaims;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\TestKeys;

final class MfaLoginTokenServiceTest extends TokenTestCase
{
    private const int TTL = 300;
    private const string AT = '2026-06-09 12:00:00';

    public function testIssuedTicketAuthenticatesBackToTheUser(): void
    {
        $config = $this->config(ttl: self::TTL);
        $clock = FrozenClock::at(self::AT);

        $token = $this->service($config, $clock)->issue('user-123');

        self::assertSame('user-123', $this->service($config, $clock)->authenticate($token));
    }

    public function testRejectsAnAccessTokenThatCarriesNoPurpose(): void
    {
        $config = $this->config(ttl: self::TTL);
        $clock = FrozenClock::at(self::AT);
        $accessToken = $this->generator($config, $clock)->generate(
            (new AccessTokenClaims('user-123', 'jti-1'))->toClaims(),
        );

        $this->expectException(InvalidTokenException::class);
        $this->service($config, $clock)->authenticate($accessToken);
    }

    public function testRejectsAForeignPurpose(): void
    {
        $config = $this->config(ttl: self::TTL);
        $clock = FrozenClock::at(self::AT);
        $stepUp = $this->generator($config, $clock)->generate(
            ['sub' => 'user-123', 'jti' => 'jti-1', 'purpose' => 'step_up'],
        );

        $this->expectException(InvalidTokenException::class);
        $this->service($config, $clock)->authenticate($stepUp);
    }

    public function testRejectsAnExpiredTicket(): void
    {
        $config = $this->config(ttl: self::TTL);
        $token = $this->service($config, FrozenClock::at(self::AT))->issue('user-123');

        // 6 minutes later — past the 5-minute TTL (plus any validator leeway).
        $later = $this->service($config, FrozenClock::at('2026-06-09 12:06:00'));

        $this->expectException(InvalidTokenException::class);
        $later->authenticate($token);
    }

    public function testRejectsATicketSignedByAnotherKey(): void
    {
        $clock = FrozenClock::at(self::AT);
        $token = $this->service($this->config(ttl: self::TTL), $clock)->issue('user-123');

        $foreign = $this->service(
            $this->config(publicKey: TestKeys::rsaAlternate()['public'], ttl: self::TTL),
            $clock,
        );

        $this->expectException(InvalidTokenException::class);
        $foreign->authenticate($token);
    }

    private function service(TokenConfiguration $config, ClockInterface $clock): MfaLoginTokenService
    {
        return new MfaLoginTokenService(
            $this->generator($config, $clock),
            new LcobucciTokenParser($config, $clock),
        );
    }
}
