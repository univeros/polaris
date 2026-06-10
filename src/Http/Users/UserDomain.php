<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Users;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\TokenInterface;

use function is_string;

/**
 * Shared helpers for the users-admin HTTP domains: building payloads, reading the authenticated
 * access token, and extracting the caller's identity/org context from its claims.
 */
abstract class UserDomain implements DomainInterface
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

    protected function forbidden(string $message): PayloadInterface
    {
        return $this->respond(403, ['error' => 'forbidden', 'message' => $message]);
    }

    protected function notFound(string $message): PayloadInterface
    {
        return $this->respond(404, ['error' => 'not_found', 'message' => $message]);
    }

    protected function actorId(TokenInterface $token): string
    {
        return (string) $token->getMetadata('sub');
    }

    /**
     * The caller's active org from the token, used to resolve their authority (`users.*` is held
     * only by `superadmin`, whose resolution is org-independent).
     */
    protected function actorOrg(TokenInterface $token): ?string
    {
        $org = $token->getMetadata('org');

        return is_string($org) && $org !== '' ? $org : null;
    }
}
