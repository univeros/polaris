<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\TokenInterface;
use Univeros\Polaris\Http\Middleware\MfaTicket;
use Univeros\Polaris\Token\ClientContext;

use function filter_var;
use function is_string;

use const FILTER_VALIDATE_EMAIL;

/**
 * Shared helpers for the auth HTTP domains: building responses, reading the client
 * context (IP), and reading the authenticated access token the auth middleware attaches.
 */
abstract class AuthDomain implements DomainInterface
{
    /**
     * @param array<string, mixed> $output
     */
    protected function respond(int $status, array $output): PayloadInterface
    {
        return (new Payload())->withStatus($status)->withOutput($output);
    }

    /**
     * @param list<string> $errors
     */
    protected function unprocessable(array $errors): PayloadInterface
    {
        return $this->respond(422, ['errors' => $errors]);
    }

    protected function client(InputCollection $input): ClientContext
    {
        $ip = $input->get(MiddlewareInterface::ATTRIBUTE_IP_ADDRESS);

        return new ClientContext(is_string($ip) ? $ip : null);
    }

    protected function isEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * The authenticated access token the `TokenAuthenticationMiddleware` attaches to the
     * request, or null on an unauthenticated request (the route is then 401).
     */
    protected function token(InputCollection $input): ?TokenInterface
    {
        $token = $input->get(TokenInterface::TOKEN_KEY);

        return $token instanceof TokenInterface ? $token : null;
    }

    /**
     * The `login_mfa` ticket the {@see MfaTokenMiddleware} attaches to a gate request, or null when
     * absent. The `instanceof` check is load-bearing: input merges request attributes with the body,
     * so only a typed {@see MfaTicket} (which a JSON value can never be) is a trusted principal — a
     * client cannot spoof one by posting the attribute key.
     */
    protected function mfaTicket(InputCollection $input): ?MfaTicket
    {
        $ticket = $input->get(MfaTicket::ATTRIBUTE);

        return $ticket instanceof MfaTicket ? $ticket : null;
    }

    protected function unauthorized(): PayloadInterface
    {
        return $this->respond(401, ['error' => 'unauthorized', 'message' => 'Authentication is required.']);
    }
}
