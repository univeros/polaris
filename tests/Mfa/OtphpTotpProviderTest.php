<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Mfa;

use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\TotpConfig;
use Univeros\Polaris\Mfa\OtphpTotpProvider;
use Univeros\Polaris\Tests\Support\FrozenClock;

use function preg_match;
use function rawurlencode;
use function str_contains;

final class OtphpTotpProviderTest extends TestCase
{
    private const string INSTANT = '2026-06-08 12:00:00';

    public function testGeneratesABase32Secret(): void
    {
        $secret = $this->provider()->generateSecret();

        self::assertNotSame('', $secret);
        self::assertSame(1, preg_match('/^[A-Z2-7]+$/', $secret), 'a base32 secret');
    }

    public function testBuildsAProvisioningUriCarryingTheSecretAndIssuer(): void
    {
        $provider = $this->provider();
        $secret = $provider->generateSecret();

        $uri = $provider->provisioningUri($secret, 'ada@example.com');

        self::assertStringStartsWith('otpauth://totp/', $uri);
        self::assertTrue(str_contains($uri, 'secret=' . $secret));
        self::assertTrue(str_contains($uri, 'issuer=' . rawurlencode('Univeros')));
    }

    public function testVerifiesTheCurrentAndInWindowCodesButRejectsOthers(): void
    {
        $clock = FrozenClock::at(self::INSTANT);
        $provider = $this->provider($clock);
        $secret = $provider->generateSecret();

        $reference = $this->reference($secret, $clock);
        $now = $clock->now()->getTimestamp();

        // Window is ±1 step (period 30s): current and adjacent steps verify; two steps out doesn't.
        self::assertTrue($provider->verify($secret, $reference->at($now)), 'current code');
        self::assertTrue($provider->verify($secret, $reference->at($now - 30)), 'previous step (in window)');
        self::assertTrue($provider->verify($secret, $reference->at($now + 30)), 'next step (in window)');
        self::assertFalse($provider->verify($secret, $reference->at($now - 60)), 'two steps back (out of window)');
        self::assertFalse($provider->verify($secret, 'abc'), 'non-numeric code');
        self::assertFalse($provider->verify($secret, ''), 'empty code');
    }

    private function provider(?FrozenClock $clock = null): OtphpTotpProvider
    {
        return new OtphpTotpProvider(TotpConfig::fromArray([]), $clock ?? FrozenClock::at(self::INSTANT));
    }

    private function reference(string $secret, FrozenClock $clock): TOTP
    {
        $totp = TOTP::createFromSecret($secret, $clock);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');

        return $totp;
    }
}
