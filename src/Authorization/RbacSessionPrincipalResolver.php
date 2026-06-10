<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;

/**
 * Resolves the session principal with multi-tenant authority for the active org — the RBAC
 * replacement for the Phase-1 {@see \Univeros\Polaris\Token\DefaultSessionPrincipalResolver}.
 *
 * It carries forward the email-verified flag from the user and asks {@see PermissionResolver} for
 * the role slugs (and, when `access_token.embed_scope` is on, the flattened permission keys) the
 * user holds in the given org. The authentication context (`mfa`/`amr`/`auth_time`) is left at its
 * defaults here, exactly as the default resolver did, so refresh/step-up keep their existing
 * semantics. With no active org (e.g. right after login) roles/scope resolve empty — the caller
 * picks an org via `POST /auth/switch-org`.
 */
final class RbacSessionPrincipalResolver implements SessionPrincipalResolverInterface
{
    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(
        private readonly RepositoryInterface $users,
        private readonly PermissionResolver $permissions,
        private readonly AuthConfig $config,
    ) {
    }

    public function resolve(string $userId, ?string $organizationId): SessionPrincipal
    {
        $user = $this->users->find($userId);
        $emailVerified = $user instanceof User && $user->emailVerifiedAt !== null;

        $authority = $this->permissions->resolve($userId, $organizationId);

        return new SessionPrincipal(
            userId: $userId,
            organizationId: $organizationId,
            roles: $authority->roles,
            scope: $this->config->accessToken->embedScope ? $authority->scope : [],
            emailVerified: $emailVerified,
        );
    }
}
