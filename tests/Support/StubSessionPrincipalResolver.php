<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;

/**
 * Resolves every user to a fixed {@see SessionPrincipal} (carrying the requested user
 * and org), so refresh tests can assert the re-minted access token without depending on
 * the real role-resolution path.
 */
final class StubSessionPrincipalResolver implements SessionPrincipalResolverInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        private readonly array $roles = [],
        private readonly bool $emailVerified = true,
    ) {
    }

    #[Override]
    public function resolve(string $userId, ?string $organizationId): SessionPrincipal
    {
        return new SessionPrincipal(
            userId: $userId,
            organizationId: $organizationId,
            roles: $this->roles,
            emailVerified: $this->emailVerified,
        );
    }
}
