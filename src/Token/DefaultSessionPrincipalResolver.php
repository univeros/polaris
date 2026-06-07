<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Persistence\Contracts\RepositoryInterface;
use Override;
use Univeros\Polaris\Entity\User;

/**
 * Default {@see SessionPrincipalResolverInterface}: resolves only the identity-level
 * context that exists before multi-tenant RBAC — the user's `email_verified` flag — and
 * leaves roles/scope empty. The RBAC phase rebinds this to a resolver that fills roles
 * and permissions for the active organization.
 */
final class DefaultSessionPrincipalResolver implements SessionPrincipalResolverInterface
{
    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(private readonly RepositoryInterface $users)
    {
    }

    #[Override]
    public function resolve(string $userId, ?string $organizationId): SessionPrincipal
    {
        $user = $this->users->find($userId);
        $emailVerified = $user instanceof User && $user->emailVerifiedAt !== null;

        return new SessionPrincipal(
            userId: $userId,
            organizationId: $organizationId,
            emailVerified: $emailVerified,
        );
    }
}
