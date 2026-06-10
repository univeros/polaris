<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Base\Action;
use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\TokenInterface;
use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Authorization\Gate;
use Univeros\Polaris\Authorization\ResolvedAuthority;

use function constant;
use function defined;
use function is_array;
use function is_string;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Enforces the permissions an Action declares (`docs/auth/rbac.md` §5a). Running just after the
 * dispatcher resolves the route and after the access-token middleware attaches the token, it reads
 * the matched domain's `public const array REQUIRES_PERMISSIONS` and short-circuits with
 * `403 forbidden` when the caller lacks any of them — otherwise the request passes through.
 *
 * Route-aware, not path-scoped: an Action with no `REQUIRES_PERMISSIONS` (or none matched) is a
 * no-op, so unprotected endpoints are untouched. The capability check is delegated to the
 * {@see Gate} (which applies the `superadmin` override); per-org scope (the path's org vs the active
 * org) is enforced by the org-scoped domains themselves.
 */
final readonly class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private Gate $gate,
        private ResponseFactoryInterface $responseFactory,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $required = $this->requiredPermissions($request);
        if ($required === []) {
            return $handler->handle($request);
        }

        $token = $request->getAttribute(TokenInterface::TOKEN_KEY);
        if (!$token instanceof TokenInterface) {
            // The access-token middleware runs first and already rejects an unauthenticated request;
            // fail closed if the ordering ever changes rather than pass a protected route through.
            return (new UnauthorizedResponder())($request, $this->responseFactory->createResponse());
        }

        $authority = $this->gate->authority($token);
        if (!$this->gate->allowsAuthority($authority, ...$required)) {
            return $this->forbidden();
        }

        // Attach the database-resolved authority so domain guards (e.g. the superadmin exemption
        // in the cross-tenant check) decide on verified roles, never on stale token claims.
        return $handler->handle($request->withAttribute(ResolvedAuthority::class, $authority));
    }

    /**
     * The permissions the matched domain requires, or an empty list when the route did not match an
     * Action or the domain declares none.
     *
     * @return list<string>
     */
    private function requiredPermissions(ServerRequestInterface $request): array
    {
        $action = $request->getAttribute(MiddlewareInterface::ATTRIBUTE_ACTION);
        if (!$action instanceof Action) {
            return [];
        }

        $constant = $action->getDomainClassName() . '::REQUIRES_PERMISSIONS';
        if (!defined($constant)) {
            return [];
        }

        $value = constant($constant);
        if (!is_array($value)) {
            return [];
        }

        $permissions = [];
        foreach ($value as $permission) {
            if (is_string($permission)) {
                $permissions[] = $permission;
            }
        }

        return $permissions;
    }

    private function forbidden(): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(403);
        $response->getBody()->write(json_encode([
            'error' => 'forbidden',
            'message' => 'You do not have permission to perform this action.',
        ], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
