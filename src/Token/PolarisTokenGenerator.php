<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Exception\InvalidTokenException;
use DateInterval;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Override;
use Psr\Clock\ClockInterface;

/**
 * Mints signed access tokens with the full Polaris claim set using lcobucci/jwt v5.
 *
 * The framework {@see \Altair\Http\Jwt\LcobucciTokenGenerator} cannot emit registered
 * claims — lcobucci's `Builder::withClaim()` throws for `sub`/`jti`/`nbf` — so this
 * generator maps them onto the dedicated builder methods (`relatedTo`, `identifiedBy`,
 * `canOnlyBeUsedAfter`) and passes everything else through as a custom claim. It also
 * stamps the `kid` header (for JWKS key selection) and derives `iat`/`exp`/`nbf` from an
 * injected PSR-20 clock, so issuance time is correct per call and controllable in tests.
 */
final class PolarisTokenGenerator implements TokenGeneratorInterface
{
    /**
     * Registered claims owned by the configuration/clock (all of `RegisteredClaims::ALL`
     * except `sub`/`jti`, which are routed to dedicated builder methods); dropped if a
     * caller passes them in `$claims` so issuance/identity stay authoritative.
     */
    private const array MANAGED_CLAIMS = ['iss', 'aud', 'iat', 'exp', 'nbf'];

    public function __construct(
        private readonly TokenConfigurationInterface $config,
        private readonly ClockInterface $clock,
        private readonly string $keyId,
    ) {
    }

    /**
     * @inheritDoc
     *
     * @param array<string, mixed> $claims
     *
     * @throws InvalidTokenException when no private key is configured for signing
     */
    #[Override]
    public function generate(array $claims = []): string
    {
        $privateKey = $this->config->getPrivateKey();

        if ($privateKey === null || $privateKey === '') {
            throw new InvalidTokenException('A private key is required to generate a token.');
        }

        $configuration = Configuration::forAsymmetricSigner(
            $this->config->getSigner(),
            InMemory::plainText($privateKey),
            InMemory::plainText($this->config->getPublicKey()),
        );

        $now = $this->clock->now();
        $expiresAt = $now->add(new DateInterval('PT' . $this->config->getTtl() . 'S'));

        $builder = $configuration->builder()
            ->issuedBy($this->config->getIssuer())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($expiresAt)
            ->withHeader('kid', $this->keyId);

        $audience = $this->config->getAudience();
        if ($audience !== null && $audience !== '') {
            $builder = $builder->permittedFor($audience);
        }

        foreach ($claims as $name => $value) {
            $builder = $this->applyClaim($builder, (string) $name, $value);
        }

        return $builder
            ->getToken($configuration->signer(), $configuration->signingKey())
            ->toString();
    }

    /**
     * Routes a single claim onto the correct builder method: registered claims use their
     * dedicated setters, protocol claims are dropped (the configuration owns them), and
     * everything else becomes a custom claim.
     */
    private function applyClaim(Builder $builder, string $name, mixed $value): Builder
    {
        if ($name === '' || \in_array($name, self::MANAGED_CLAIMS, true)) {
            return $builder;
        }

        return match ($name) {
            'sub' => $builder->relatedTo((string) $value),
            'jti' => $builder->identifiedBy((string) $value),
            default => $builder->withClaim($name, $value),
        };
    }
}
