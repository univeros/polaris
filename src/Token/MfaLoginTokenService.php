<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Exception\InvalidTokenException;
use Symfony\Component\Uid\Uuid;

/**
 * Mints and authenticates the short-lived `login_mfa` ticket that bridges a password success to
 * the MFA challenge/verify step.
 *
 * The ticket is an ordinary signed JWT (same key/issuer/audience as access tokens) carrying a
 * `purpose=login_mfa` claim and a short TTL (`auth.mfa.login_token_ttl`). That `purpose` claim is
 * exactly what {@see PolarisTokenParser} refuses, so the ticket can never authenticate a normal
 * route — only the MFA gate, which authenticates it here. The parser injected here is the
 * framework parser (not the purpose-rejecting Polaris one) so it accepts the ticket; this service
 * then enforces that the purpose is precisely `login_mfa` and that a subject is present.
 */
final readonly class MfaLoginTokenService
{
    /** The `purpose` claim that marks a token as a login-MFA ticket. */
    public const string PURPOSE = 'login_mfa';

    public function __construct(
        private TokenGeneratorInterface $generator,
        private TokenParserInterface $parser,
    ) {
    }

    /**
     * Mint a `login_mfa` ticket for the user who has cleared the password step. Issuance time,
     * expiry, issuer, and audience are owned by the generator's configuration/clock.
     */
    public function issue(string $userId): string
    {
        return $this->generator->generate([
            'sub' => $userId,
            'jti' => Uuid::v7()->toRfc4122(),
            'purpose' => self::PURPOSE,
        ]);
    }

    /**
     * Validate a presented ticket and return its subject (the user id). Signature, issuer,
     * audience, and time are checked by the parser; this adds the `purpose=login_mfa` and
     * non-empty-subject constraints.
     *
     * @throws InvalidTokenException the token is invalid, expired, not a login-MFA ticket, or
     *                               carries no subject
     */
    public function authenticate(string $token): string
    {
        $parsed = $this->parser->parse($token);

        if ($parsed->getMetadata('purpose') !== self::PURPOSE) {
            throw new InvalidTokenException('The token is not a login-MFA ticket.');
        }

        $subject = (string) $parsed->getMetadata('sub');
        if ($subject === '') {
            throw new InvalidTokenException('The login-MFA ticket carries no subject.');
        }

        return $subject;
    }
}
