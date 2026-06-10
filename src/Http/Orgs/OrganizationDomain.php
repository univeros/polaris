<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\TokenInterface;
use Univeros\Polaris\Authorization\PermissionCatalog;

use function in_array;
use function is_array;

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

    protected function forbidden(string $message): PayloadInterface
    {
        return $this->respond(403, ['error' => 'forbidden', 'message' => $message]);
    }

    protected function notFound(string $message): PayloadInterface
    {
        return $this->respond(404, ['error' => 'not_found', 'message' => $message]);
    }

    /**
     * Cross-tenant guard: the path's organization must equal the caller's active org (the token's
     * `org` claim) — a `superadmin` may act on any org. Returns true when the request must be denied.
     */
    protected function deniesActiveOrg(TokenInterface $token, string $organizationId): bool
    {
        $roles = $token->getMetadata('roles');
        $isSuperadmin = is_array($roles) && in_array(PermissionCatalog::ROLE_SUPERADMIN, $roles, true);

        return !$isSuperadmin && $organizationId !== $token->getMetadata('org');
    }
}
