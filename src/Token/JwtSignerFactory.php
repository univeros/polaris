<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Univeros\Polaris\Exception\InvalidConfigException;

/**
 * Maps the configured access-token algorithm ({@see \Univeros\Polaris\Config\AccessTokenConfig})
 * to a concrete lcobucci/jwt asymmetric {@see Signer}.
 *
 * Only asymmetric algorithms are offered: the private key signs and the public key
 * (published via JWKS) verifies, so resource servers can validate tokens they can
 * never mint. The algorithm string doubles as the JWA `alg` value advertised in the
 * token header and JWKS.
 */
final class JwtSignerFactory
{
    public const string RS256 = 'RS256';
    public const string EDDSA = 'EdDSA';

    public static function create(string $algorithm): Signer
    {
        return match ($algorithm) {
            self::RS256 => new Sha256(),
            self::EDDSA => new Eddsa(),
            default => throw new InvalidConfigException(
                "Unsupported access-token signer '$algorithm'; expected RS256 or EdDSA.",
            ),
        };
    }
}
