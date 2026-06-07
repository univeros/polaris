<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Univeros\Polaris\Tests\Support\FrozenClock;
use Univeros\Polaris\Token\AccessTokenClaims;
use Univeros\Polaris\Token\PolarisTokenValidator;

final class PolarisTokenValidatorTest extends TokenTestCase
{
    public function testAcceptsAValidToken(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');
        $jwt = $this->generator($config, $clock)->generate(
            (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims(),
        );

        self::assertTrue((new PolarisTokenValidator($this->parser($config, $clock)))->validate($jwt));
    }

    public function testRejectsAMalformedToken(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        self::assertFalse((new PolarisTokenValidator($this->parser($config, $clock)))->validate('not-a-token'));
    }

    public function testRejectsASinglePurposeTokenOnTheAccessPath(): void
    {
        $config = $this->config();
        $clock = FrozenClock::at('2026-06-07 12:00:00');

        $claims = (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims();
        $claims['purpose'] = 'login_mfa';
        $jwt = $this->generator($config, $clock)->generate($claims);

        // A correctly-signed, in-window token is still refused because it is a
        // single-purpose (mfa/step-up) ticket, not a general access token.
        self::assertFalse((new PolarisTokenValidator($this->parser($config, $clock)))->validate($jwt));
    }
}
