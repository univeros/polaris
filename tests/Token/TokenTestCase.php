<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Token;

use Altair\Http\Support\TokenConfiguration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Token\PolarisTokenGenerator;
use Univeros\Polaris\Token\PolarisTokenParser;
use Univeros\Polaris\Tests\Support\TestKeys;

use function base64_decode;
use function explode;
use function json_decode;
use function strtr;

/**
 * Shared scaffolding for token tests: builds a {@see TokenConfiguration} over the
 * generated RSA test keys and constructs the Polaris generator/parser against an
 * injectable clock.
 */
abstract class TokenTestCase extends TestCase
{
    protected const string ISSUER = 'https://auth.polaris.test';
    protected const string AUDIENCE = 'https://api.polaris.test';
    protected const string KID = 'test-kid-1';

    protected function config(
        ?string $publicKey = null,
        ?string $privateKey = null,
        string $issuer = self::ISSUER,
        ?string $audience = self::AUDIENCE,
        int $ttl = 900,
    ): TokenConfiguration {
        $keys = TestKeys::rsa();

        return new TokenConfiguration(
            $publicKey ?? $keys['public'],
            $ttl,
            new Sha256(),
            $issuer,
            null,
            $privateKey ?? $keys['private'],
            $audience,
        );
    }

    protected function generator(TokenConfiguration $config, ClockInterface $clock): PolarisTokenGenerator
    {
        return new PolarisTokenGenerator($config, $clock, self::KID);
    }

    protected function parser(TokenConfiguration $config, ClockInterface $clock): PolarisTokenParser
    {
        return new PolarisTokenParser($config, $clock);
    }

    /**
     * Decodes a JWT's protected header to JSON-decoded form (for asserting `kid`/`alg`).
     *
     * @return array<string, mixed>
     */
    protected function header(string $jwt): array
    {
        $segment = explode('.', $jwt)[0];
        /** @var array<string, mixed> $decoded */
        $decoded = (array) json_decode((string) base64_decode(strtr($segment, '-_', '+/'), true), true);

        return $decoded;
    }
}
