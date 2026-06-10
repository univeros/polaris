<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\TokenInterface;
use DateTimeImmutable;
use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Token\AccessTokenDenylist;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Optional instant access-token revocation (`security.access_token.denylist`, default off): after
 * the access-token middleware attaches the token, reject it with `401 session_ended` when the
 * user's denylist watermark covers its `iat` — so logout-everywhere, disable, and erase take
 * effect immediately instead of after the access TTL. One cache read per authenticated request;
 * a no-op when the flag is off or the request carries no token.
 */
final readonly class DenylistMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AccessTokenDenylist $denylist,
        private AuthConfig $config,
        private ResponseFactoryInterface $responseFactory,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->config->accessToken->denylist) {
            return $handler->handle($request);
        }

        $token = $request->getAttribute(TokenInterface::TOKEN_KEY);
        if (!$token instanceof TokenInterface) {
            return $handler->handle($request);
        }

        // PolarisTokenParser guarantees sub and a DateTimeImmutable iat on every token it accepts;
        // a token without them did not come through it, so with the flag on we fail closed.
        $userId = (string) $token->getMetadata('sub');
        $issuedAt = $token->getMetadata('iat');
        if ($userId === '' || !$issuedAt instanceof DateTimeImmutable || $this->denylist->isRevoked($userId, $issuedAt)) {
            $response = $this->responseFactory->createResponse(401)
                ->withHeader('Content-Type', 'application/json');
            $response->getBody()->write(json_encode(
                ['error' => 'session_ended', 'message' => 'The session is no longer active.'],
                JSON_THROW_ON_ERROR,
            ));

            return $response;
        }

        return $handler->handle($request);
    }
}
