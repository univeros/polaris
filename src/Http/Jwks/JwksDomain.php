<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Jwks;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Token\JwkSet;

/**
 * Domain behind `GET /auth/.well-known/jwks.json`: serves the public signing key as a
 * JWK Set keyed by `kid`, so resource servers can verify access tokens.
 *
 * The endpoint is public (no secrets are exposed — only the public key) and depends only
 * on the validated {@see Secrets} and {@see AuthConfig} bound at boot.
 */
final class JwksDomain implements DomainInterface
{
    public function __construct(
        private readonly Secrets $secrets,
        private readonly AuthConfig $config,
    ) {
    }

    /**
     * @inheritDoc
     */
    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $jwks = JwkSet::fromPublicKey(
            $this->secrets->jwtPublicKey,
            $this->secrets->jwtKid,
            $this->config->accessToken->signer,
        );

        return (new Payload())->withStatus(200)->withOutput($jwks);
    }
}
