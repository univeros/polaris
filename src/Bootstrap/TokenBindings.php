<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Contracts\TokenValidatorInterface;
use Altair\Http\Jwt\SystemClock;
use Altair\Http\Support\TokenConfiguration;
use Psr\Clock\ClockInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Univeros\Polaris\Token\JwtSignerFactory;
use Univeros\Polaris\Token\PolarisTokenFactory;
use Univeros\Polaris\Token\PolarisTokenGenerator;
use Univeros\Polaris\Token\PolarisTokenParser;
use Univeros\Polaris\Token\PolarisTokenValidator;

/**
 * Wires the JWT machinery: the token configuration, the Polaris generator, and the
 * parser/validator/factory that verify tokens, plus the public JWKS document.
 */
final class TokenBindings
{
    public function apply(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $this->bindTokens($container, $authConfig, $secrets);
    }

    /**
     * Bind the JWT machinery: a {@see TokenConfigurationInterface} derived from
     * {@see AuthConfig} (issuer/audience/ttl/signer) and {@see Secrets} (keys), the
     * Polaris generator (full claim set + `kid` header), and the parser/validator/factory
     * that verify tokens against the public key. Issuance time (`iat`/`exp`/`nbf`) is
     * derived from the injected {@see ClockInterface} at mint time, not from the
     * configuration, so the configuration carries only static values.
     */
    private function bindTokens(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $container->singleton(ClockInterface::class, SystemClock::class);

        $container->singleton(
            TokenConfigurationInterface::class,
            static function () use ($authConfig, $secrets): TokenConfiguration {
                $publicKey = $secrets->jwtPublicKey;
                $issuer = $authConfig->issuer;
                if ($publicKey === '' || $issuer === '') {
                    throw new InvalidConfigException('A JWT public key and issuer are required to mint tokens.');
                }

                return new TokenConfiguration(
                    $publicKey,
                    $authConfig->accessToken->ttl,
                    JwtSignerFactory::create($authConfig->accessToken->signer),
                    $issuer,
                    null,
                    $secrets->jwtPrivateKey,
                    $authConfig->audience,
                );
            },
        );

        $keyId = $secrets->jwtKid;
        $container->singleton(
            TokenGeneratorInterface::class,
            static fn(TokenConfigurationInterface $config, ClockInterface $clock): PolarisTokenGenerator
                => new PolarisTokenGenerator($config, $clock, $keyId),
        );

        $container->singleton(TokenParserInterface::class, PolarisTokenParser::class);
        $container->singleton(TokenValidatorInterface::class, PolarisTokenValidator::class);
        $container->singleton(TokenFactoryInterface::class, PolarisTokenFactory::class);
        $container->singleton(JwksDomain::class);
    }
}
