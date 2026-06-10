<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Cycle\ORM\ORMInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Authorization\RbacSessionPrincipalResolver;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Event\NullEventDispatcher;
use Univeros\Polaris\Http\Auth\LogoutAllDomain;
use Univeros\Polaris\Http\Auth\LogoutDomain;
use Univeros\Polaris\Http\Auth\RefreshTokenDomain;
use Univeros\Polaris\Http\Auth\RevokeSessionDomain;
use Univeros\Polaris\Http\Auth\SessionsDomain;
use Univeros\Polaris\Http\Auth\SwitchOrgDomain;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Persistence\MembershipRepository;
use Univeros\Polaris\Persistence\MembershipRoleRepository;
use Univeros\Polaris\Persistence\OrganizationRepository;
use Univeros\Polaris\Persistence\PermissionRepository;
use Univeros\Polaris\Persistence\RefreshTokenRepository;
use Univeros\Polaris\Persistence\RolePermissionRepository;
use Univeros\Polaris\Persistence\RoleRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\AccessTokenDenylist;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

/**
 * Wires the session machinery: refresh-token issuance and rotation via {@see TokenService},
 * the RBAC session principal resolver, and the refresh + session-management endpoints.
 */
final class SessionBindings
{
    public function apply(Container $container): void
    {
        $this->bindSessions($container);
        $this->bindSessionEndpoints($container);
    }

    /**
     * Bind the session machinery: the keyed {@see Pepper} (refresh-token hashing), a
     * no-op PSR-14 dispatcher (until the host wires listeners in Phase 4), the
     * {@see PermissionResolver} and the {@see RbacSessionPrincipalResolver} (which embeds the active
     * org's roles/scope into issued tokens), the {@see SwitchOrgDomain}, and {@see TokenService},
     * which issues and rotates refresh tokens with reuse detection.
     */
    private function bindSessions(Container $container): void
    {
        $container->singleton(Pepper::class, static fn(Secrets $secrets): Pepper => new Pepper($secrets->appKey));

        // Only fall back to the no-op dispatcher when the host has not wired a real one,
        // so a host-provided PSR-14 dispatcher (and its security listeners) is preserved.
        if (!$container->has(EventDispatcherInterface::class)) {
            $container->singleton(EventDispatcherInterface::class, NullEventDispatcher::class);
        }
        $container->singleton(
            PermissionResolver::class,
            static fn(
                UserRepository $users,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
            ): PermissionResolver => new PermissionResolver(
                $users,
                $organizations,
                $memberships,
                $membershipRoles,
                $roles,
                $rolePermissions,
                $permissions,
            ),
        );

        // The RBAC resolver replaces the Phase-1 default: it embeds the user's roles (and, when
        // access_token.embed_scope is on, the flattened permission scope) for the active org.
        $container->singleton(
            SessionPrincipalResolverInterface::class,
            static fn(
                UserRepository $users,
                PermissionResolver $permissions,
                AuthConfig $config,
            ): RbacSessionPrincipalResolver => new RbacSessionPrincipalResolver($users, $permissions, $config),
        );

        $container->singleton(
            SwitchOrgDomain::class,
            static fn(
                TokenService $tokens,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                AuthConfig $config,
            ): SwitchOrgDomain => new SwitchOrgDomain($tokens, $organizations, $memberships, $config),
        );

        $container->singleton(
            TokenService::class,
            static fn(
                ORMInterface $orm,
                RefreshTokenRepository $refreshTokens,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                TokenGeneratorInterface $accessTokens,
                SessionPrincipalResolverInterface $principals,
                AuthConfig $config,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): TokenService => new TokenService(
                $refreshTokens,
                $unitOfWork,
                $pepper,
                $accessTokens,
                $principals,
                $config,
                $clock,
                $events,
                $orm,
            ),
        );
    }

    /**
     * Bind the refresh + session-management endpoints: {@see SessionService} and the
     * domains behind `/auth/token/refresh`, `/auth/logout`, `/auth/logout-all`, and
     * `/auth/sessions`. The mutating session endpoints read the access token the auth
     * middleware (issue #15) attaches to the request.
     */
    private function bindSessionEndpoints(Container $container): void
    {
        $container->singleton(
            SessionService::class,
            static fn(
                RefreshTokenRepository $refreshTokens,
                TokenService $tokens,
                ClockInterface $clock,
                EventDispatcherInterface $events,
                AccessTokenDenylist $denylist,
            ): SessionService => new SessionService($refreshTokens, $tokens, $clock, $events, $denylist),
        );

        $container->singleton(RefreshTokenDomain::class);
        $container->singleton(LogoutDomain::class);
        $container->singleton(LogoutAllDomain::class);
        $container->singleton(SessionsDomain::class);
        $container->singleton(RevokeSessionDomain::class);
    }
}
