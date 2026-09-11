<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenFactoryInterface as AltairTokenFactory;
use Altair\Http\Contracts\TokenInterface as AltairToken;
use Altair\Http\Exception\AuthorizationTokenException as AltairAuthorizationTokenException;
use Altair\Http\Exception\InvalidTokenException as AltairInvalidTokenException;
use Override;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Exception\InvalidTokenException;

/**
 * The Polaris token factory under the framework's contract: tokens come back as {@see DualToken}
 * and the Polaris exceptions are rethrown as the framework's, so the framework's authentication
 * middleware keeps answering 401 (invalid or expired token) and 403 (no token to issue).
 */
final readonly class TokenFactoryBridge implements AltairTokenFactory
{
    public function __construct(private TokenFactoryInterface $factory)
    {
    }

    #[Override]
    public function fromTokenString(string $token): AltairToken
    {
        try {
            return new DualToken($this->factory->fromTokenString($token));
        } catch (InvalidTokenException $exception) {
            throw new AltairInvalidTokenException($exception->getMessage(), $exception);
        } catch (AuthorizationTokenException $exception) {
            throw new AltairAuthorizationTokenException($exception->getMessage(), $exception);
        }
    }

    #[Override]
    public function fromCredentials(array $credentials): AltairToken
    {
        try {
            return new DualToken($this->factory->fromCredentials($credentials));
        } catch (InvalidTokenException $exception) {
            throw new AltairInvalidTokenException($exception->getMessage(), $exception);
        } catch (AuthorizationTokenException $exception) {
            throw new AltairAuthorizationTokenException($exception->getMessage(), $exception);
        }
    }
}
