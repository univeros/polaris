<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\TokenInterface;

/**
 * Shared helpers for the organization HTTP domains: building payloads and reading the authenticated
 * access token the {@see \Univeros\Polaris\Http\Middleware\TokenAuthenticationMiddleware} attaches.
 */
abstract class OrganizationDomain implements DomainInterface
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

    /**
     * The authenticated access token, or null on an unauthenticated request (the route is then 401).
     */
    protected function token(InputCollection $input): ?TokenInterface
    {
        $token = $input->get(TokenInterface::TOKEN_KEY);

        return $token instanceof TokenInterface ? $token : null;
    }

    protected function unauthorized(): PayloadInterface
    {
        return $this->respond(401, ['error' => 'unauthorized', 'message' => 'Authentication is required.']);
    }
}
