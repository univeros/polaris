<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Altair\Http\Contracts\TokenInterface as AltairToken;
use Altair\Http\Exception\AuthorizationTokenException as AltairAuthorizationTokenException;
use Altair\Http\Exception\InvalidTokenException as AltairInvalidTokenException;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Exception\InvalidTokenException;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Tests\Support\TestPolaris;
use Univeros\Polaris\Token\DualToken;
use Univeros\Polaris\Token\TokenFactoryBridge;

final class TokenFactoryBridgeTest extends TestCase
{
    public function testAValidAccessTokenComesBackAsADualToken(): void
    {
        $graph = $this->graph();
        $jwt = TestPolaris::accessToken($graph, 'user-3');

        $token = (new TokenFactoryBridge($graph->tokenFactory()))->fromTokenString($jwt);

        self::assertInstanceOf(DualToken::class, $token);
        self::assertInstanceOf(AltairToken::class, $token);
        self::assertInstanceOf(TokenInterface::class, $token);
        self::assertSame($jwt, $token->getToken());
        self::assertSame('user-3', $token->getMetadata('sub'));
        self::assertSame(TestPolaris::ISSUER, $token->getMetadata('iss'));
    }

    public function testAMalformedTokenIsTheFrameworksInvalidTokenException(): void
    {
        $bridge = new TokenFactoryBridge($this->graph()->tokenFactory());

        try {
            $bridge->fromTokenString('not.a.jwt');
            self::fail('expected the framework exception');
        } catch (AltairInvalidTokenException $exception) {
            self::assertInstanceOf(InvalidTokenException::class, $exception->getPrevious());
            self::assertSame($exception->getPrevious()->getMessage(), $exception->getMessage());
        }
    }

    public function testAnExpiredTokenIsTheFrameworksInvalidTokenException(): void
    {
        $jwt = TestPolaris::accessToken($this->graph(FrozenClock::at('2026-01-01 00:00:00')));
        $bridge = new TokenFactoryBridge($this->graph(FrozenClock::at('2026-09-11 00:00:00'))->tokenFactory());

        $this->expectException(AltairInvalidTokenException::class);
        $bridge->fromTokenString($jwt);
    }

    public function testCredentialsForNoOneAreTheFrameworksAuthorizationTokenException(): void
    {
        $bridge = new TokenFactoryBridge($this->graph()->tokenFactory());

        try {
            $bridge->fromCredentials(['user' => 'ghost@example.com', 'password' => 'secret']);
            self::fail('expected the framework exception');
        } catch (AltairAuthorizationTokenException $exception) {
            self::assertInstanceOf(AuthorizationTokenException::class, $exception->getPrevious());
        }
    }

    public function testATokenIssuedForCredentialsIsWrappedToo(): void
    {
        $issued = $this->graph()->tokenFactory()->fromTokenString(TestPolaris::accessToken($this->graph(), 'user-9'));
        $factory = new class ($issued) implements TokenFactoryInterface {
            public function __construct(private readonly TokenInterface $token)
            {
            }

            public function fromTokenString(string $token): TokenInterface
            {
                return $this->token;
            }

            public function fromCredentials(array $credentials): TokenInterface
            {
                return $this->token;
            }
        };

        $token = (new TokenFactoryBridge($factory))->fromCredentials(['user' => 'ada@example.com', 'password' => 'secret']);

        self::assertInstanceOf(DualToken::class, $token);
        self::assertSame('user-9', $token->getMetadata('sub'));
    }

    private function graph(?ClockInterface $clock = null): Graph
    {
        return Polaris::create(new Config(TestPolaris::secrets(), TestPolaris::auth(), new InMemoryAdapter(), clock: $clock))->graph();
    }
}
