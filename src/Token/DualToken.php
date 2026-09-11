<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenInterface as AltairToken;
use Override;
use Polaris\Contract\TokenInterface;

/**
 * One token satisfying both contracts: the framework's, which its `TokenAuthenticationMiddleware`
 * stores on the request under `TokenInterface::TOKEN_KEY`, and Polaris's, which the services read.
 */
final readonly class DualToken implements AltairToken, TokenInterface
{
    public function __construct(private TokenInterface $token)
    {
    }

    #[Override]
    public function getToken(): string
    {
        return $this->token->getToken();
    }

    #[Override]
    public function getMetadata(?string $key = null): mixed
    {
        return $this->token->getMetadata($key);
    }
}
