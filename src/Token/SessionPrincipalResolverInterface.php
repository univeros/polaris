<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

/**
 * Resolves the {@see SessionPrincipal} for a user (and active org) when a session's
 * access token is (re-)minted — notably on refresh, where the authorization context is
 * re-resolved so permission changes take effect within one access-TTL window.
 *
 * The default ({@see DefaultSessionPrincipalResolver}) returns the identity with no
 * roles; the multi-tenant RBAC phase rebinds this to resolve real org roles/permissions.
 */
interface SessionPrincipalResolverInterface
{
    public function resolve(string $userId, ?string $organizationId): SessionPrincipal;
}
