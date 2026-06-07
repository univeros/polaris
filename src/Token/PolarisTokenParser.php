<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Exception\InvalidTokenException;
use Altair\Http\Jwt\LcobucciTokenParser;
use Override;
use Psr\Clock\ClockInterface;

/**
 * Parses and validates access tokens, delegating signature/issuer/audience/time checks
 * to the framework {@see LcobucciTokenParser}, then enforcing two Polaris-specific rules:
 *
 * 1. A general access token must NOT carry a `purpose` claim. Single-purpose JWTs (the
 *    `mfa_token` and `step_up` tickets) are signed by the same key and would otherwise
 *    pass generic validation; rejecting any token bearing a `purpose` claim stops them
 *    from authenticating normal routes (see `docs/auth/flows.md`).
 * 2. The time claims `exp` and `iat` must be present. The framework's `LooseValidAt`
 *    constraint treats a missing `exp` as "never expires" and a missing `iat` as valid,
 *    so requiring them here closes that bypass for tokens this service accepts.
 */
final class PolarisTokenParser implements TokenParserInterface
{
    /** Time claims an access token must carry (defence against missing-claim bypass). */
    private const array REQUIRED_TIME_CLAIMS = ['iat', 'exp'];

    private readonly LcobucciTokenParser $delegate;

    public function __construct(TokenConfigurationInterface $config, ?ClockInterface $clock = null)
    {
        $this->delegate = new LcobucciTokenParser($config, $clock);
    }

    /**
     * @inheritDoc
     *
     * @throws InvalidTokenException
     */
    #[Override]
    public function parse(string $token): TokenInterface
    {
        $parsed = $this->delegate->parse($token);

        // Any `purpose` claim (of any type) marks a single-purpose ticket, not an access token.
        if ($parsed->getMetadata('purpose') !== null) {
            throw new InvalidTokenException('A single-purpose token cannot be used as an access token.');
        }

        foreach (self::REQUIRED_TIME_CLAIMS as $claim) {
            if ($parsed->getMetadata($claim) === null) {
                throw new InvalidTokenException("Access token is missing the required '$claim' claim.");
            }
        }

        return $parsed;
    }
}
