<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Exception\AuthorizationTokenException;
use Override;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function is_string;

/**
 * Builds {@see TokenInterface}s for the framework auth middleware.
 *
 * `fromTokenString()` parses and validates an incoming bearer token. `fromCredentials()`
 * mints a token for already-validated credentials (the HTTP-basic path): it resolves the
 * subject via the {@see IdentityProviderInterface} and issues a minimal access token.
 *
 * Org/roles/session (`sid`) enrichment belongs to the interactive login flow
 * ({@see \Univeros\Polaris\Module} Phase 1 — `LoginService`/`TokenService`), which calls
 * the generator with a fully-resolved {@see AccessTokenClaims}; this factory deliberately
 * issues an unscoped token for the basic-credentials path.
 */
final class PolarisTokenFactory implements TokenFactoryInterface
{
    public function __construct(
        private readonly TokenParserInterface $parser,
        private readonly TokenGeneratorInterface $generator,
        private readonly IdentityProviderInterface $identities,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @inheritDoc
     */
    #[Override]
    public function fromTokenString(string $token): TokenInterface
    {
        return $this->parser->parse($token);
    }

    /**
     * @inheritDoc
     *
     * @param array<array-key, mixed> $credentials list (`[user, password]`) or assoc shape
     *
     * @throws AuthorizationTokenException when the credentials resolve to no usable subject
     */
    #[Override]
    public function fromCredentials(array $credentials): TokenInterface
    {
        $username = $this->username($credentials);
        $record = $username === null ? null : $this->identities->findOneBy(['email' => $username]);

        if ($record === null) {
            throw new AuthorizationTokenException('Cannot issue a token for the supplied credentials.');
        }

        $subject = (string) ($record['id'] ?? '');
        if ($subject === '') {
            throw new AuthorizationTokenException('The identity record has no subject identifier.');
        }

        $claims = new AccessTokenClaims(
            subject: $subject,
            jwtId: Uuid::v7()->toRfc4122(),
            amr: ['pwd'],
            authTime: $this->clock->now()->getTimestamp(),
        );

        return $this->parser->parse($this->generator->generate($claims->toClaims()));
    }

    /**
     * Extracts the username from either the extractor's `[user, password]` list shape or
     * an associative `['user' => …]` shape.
     *
     * @param array<array-key, mixed> $credentials
     */
    private function username(array $credentials): ?string
    {
        $user = $credentials[0] ?? $credentials['user'] ?? null;

        return is_string($user) && $user !== '' ? $user : null;
    }
}
