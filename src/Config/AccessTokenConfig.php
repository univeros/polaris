<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Univeros\Polaris\Exception\InvalidConfigException;

use function in_array;

/**
 * Access-token (JWT) settings: lifetime, signing algorithm, and claim/revocation strategy.
 */
final readonly class AccessTokenConfig
{
    private const SIGNERS = ['RS256', 'EdDSA'];

    public function __construct(
        public int $ttl,
        public string $signer,
        public bool $embedScope,
        public bool $denylist,
    ) {
        if ($ttl <= 0) {
            throw new InvalidConfigException('auth.access_token.ttl must be a positive integer.');
        }

        if (!in_array($signer, self::SIGNERS, true)) {
            throw new InvalidConfigException(
                'auth.access_token.signer must be one of: ' . implode(', ', self::SIGNERS) . '.',
            );
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            ttl: (int) ($data['ttl'] ?? 900),
            signer: (string) ($data['signer'] ?? 'RS256'),
            embedScope: (bool) ($data['embed_scope'] ?? false),
            denylist: (bool) ($data['denylist'] ?? false),
        );
    }
}
