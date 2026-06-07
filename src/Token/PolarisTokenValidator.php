<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Contracts\TokenValidatorInterface;
use Altair\Http\Exception\AuthorizationTokenException;
use Override;

/**
 * Boolean validity check over {@see PolarisTokenParser}: a token is valid when it parses
 * and passes every constraint, and invalid when parsing throws. Useful where a caller
 * wants a yes/no answer without handling the parsed token or catching exceptions.
 */
final class PolarisTokenValidator implements TokenValidatorInterface
{
    public function __construct(private readonly TokenParserInterface $parser)
    {
    }

    /**
     * @inheritDoc
     */
    #[Override]
    public function validate(string $token): bool
    {
        try {
            $this->parser->parse($token);

            return true;
        } catch (AuthorizationTokenException) {
            // Covers InvalidTokenException and any other authorization-token failure.
            return false;
        }
    }
}
