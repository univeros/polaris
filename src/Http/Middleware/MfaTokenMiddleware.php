<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\HttpAuthRuleInterface;
use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Exception\InvalidTokenException;
use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Token\MfaLoginTokenService;

/**
 * Authenticates the short-lived `login_mfa` ticket on the MFA-gate routes
 * (`/auth/mfa/challenge` and `/auth/mfa/verify`).
 *
 * Those routes are passed through by the access-token {@see \Altair\Http\Middleware\TokenAuthenticationMiddleware}
 * (whose {@see \Univeros\Polaris\Token\PolarisTokenParser} would reject the ticket's `purpose`
 * claim), so this middleware is what guards them: scoped by an {@see HttpAuthRuleInterface} to the
 * gate paths, it pulls the bearer, validates it through {@see MfaLoginTokenService}, and attaches
 * the resolved user id as a request attribute the gate domains read (mirroring how the IP address
 * flows). A missing or invalid ticket is a `401` (the same envelope as {@see UnauthorizedResponder});
 * any request outside the gate passes straight through, untouched.
 */
final readonly class MfaTokenMiddleware implements MiddlewareInterface
{
    public function __construct(
        private HttpAuthRuleInterface $rule,
        private TokenExtractorInterface $bearer,
        private MfaLoginTokenService $tickets,
        private ResponseFactoryInterface $responseFactory,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!($this->rule)($request)) {
            return $handler->handle($request);
        }

        $token = $this->bearer->extract($request);
        if ($token === null) {
            return $this->unauthorized($request);
        }

        try {
            $userId = $this->tickets->authenticate($token);
        } catch (InvalidTokenException) {
            return $this->unauthorized($request);
        }

        return $handler->handle($request->withAttribute(MfaTicket::ATTRIBUTE, new MfaTicket($userId)));
    }

    private function unauthorized(ServerRequestInterface $request): ResponseInterface
    {
        return (new UnauthorizedResponder())($request, $this->responseFactory->createResponse());
    }
}
