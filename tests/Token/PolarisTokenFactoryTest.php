<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Exception\AuthorizationTokenException;
use Altair\Http\Support\TokenConfiguration;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Tests\Support\StubIdentityProvider;
use Univeros\Polaris\Token\AccessTokenClaims;
use Univeros\Polaris\Token\PolarisTokenFactory;

final class PolarisTokenFactoryTest extends TokenTestCase
{
    private function factory(
        TokenConfiguration $config,
        ClockInterface $clock,
        IdentityProviderInterface $identities,
    ): PolarisTokenFactory {
        return new PolarisTokenFactory(
            $this->parser($config, $clock),
            $this->generator($config, $clock),
            $identities,
            $clock,
        );
    }

    public function testFromCredentialsMintsATokenForTheResolvedSubject(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');
        $identities = new StubIdentityProvider([
            'ada@example.com' => ['id' => 'user-9', 'email' => 'ada@example.com'],
        ]);

        $token = $this->factory($config, $clock, $identities)->fromCredentials(['ada@example.com', 'secret']);

        self::assertSame('user-9', $token->getMetadata('sub'));
        self::assertSame(['pwd'], $token->getMetadata('amr'));
        self::assertNull($token->getMetadata('org'));
    }

    public function testFromCredentialsRejectsAnUnknownUser(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        $this->expectException(AuthorizationTokenException::class);
        $this->factory($config, $clock, new StubIdentityProvider())->fromCredentials(['ghost@example.com', 'x']);
    }

    public function testFromTokenStringParsesAValidToken(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');
        $jwt = $this->generator($config, $clock)->generate(
            (new AccessTokenClaims(subject: 'user-5', jwtId: 'jti-5'))->toClaims(),
        );

        $token = $this->factory($config, $clock, new StubIdentityProvider())->fromTokenString($jwt);

        self::assertSame('user-5', $token->getMetadata('sub'));
    }
}
