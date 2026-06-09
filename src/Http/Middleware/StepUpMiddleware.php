<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\HttpAuthRuleInterface;
use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\TokenInterface;
use Override;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;

use function is_int;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Guards the sensitive routes that require a **recent** strong authentication (spec §7): change
 * password, regenerate recovery codes, remove an MFA factor, …
 *
 * Scoped by an {@see HttpAuthRuleInterface} to those routes, it runs after the access-token
 * middleware (so the token is attached) and enforces `now - auth_time <= security.step_up.max_age`
 * — but only for users who actually have a confirmed factor, since step-up is meaningless (and
 * unsatisfiable) without one. When the authentication is stale it short-circuits with
 * `401 step_up_required` and points the client at `POST /auth/mfa/step-up`; otherwise the request
 * passes through. Every other route is untouched.
 */
final readonly class StepUpMiddleware implements MiddlewareInterface
{
    private const string STEP_UP_ENDPOINT = '/auth/mfa/step-up';

    public function __construct(
        private HttpAuthRuleInterface $rule,
        private MfaChallengeVerifier $verifier,
        private AuthConfig $config,
        private ClockInterface $clock,
        private ResponseFactoryInterface $responseFactory,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!($this->rule)($request)) {
            return $handler->handle($request);
        }

        $token = $request->getAttribute(TokenInterface::TOKEN_KEY);
        if (!$token instanceof TokenInterface) {
            // The access-token middleware (which runs first) already rejects an unauthenticated
            // request, so this is a dead path in the wired pipeline — but fail closed rather than
            // pass a tokenless request through to a sensitive domain if the ordering ever changes.
            return (new UnauthorizedResponder())($request, $this->responseFactory->createResponse());
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '' || !$this->verifier->hasConfirmedFactor($userId)) {
            // No MFA on this account → step-up does not apply.
            return $handler->handle($request);
        }

        if ($this->isRecent($token)) {
            return $handler->handle($request);
        }

        return $this->stepUpRequired();
    }

    private function isRecent(TokenInterface $token): bool
    {
        $authTime = $token->getMetadata('auth_time');
        if (!is_int($authTime)) {
            // A token with no auth_time can never be "recent" — require a step-up.
            return false;
        }

        return ($this->clock->now()->getTimestamp() - $authTime) <= $this->config->stepUpMaxAge;
    }

    private function stepUpRequired(): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(401);
        $response->getBody()->write(json_encode([
            'error' => 'step_up_required',
            'message' => 'This operation requires a recent re-authentication.',
            'step_up' => self::STEP_UP_ENDPOINT,
        ], JSON_THROW_ON_ERROR));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('WWW-Authenticate', 'Bearer error="step_up_required"');
    }
}
