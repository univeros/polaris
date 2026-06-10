<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Http\Contracts\TokenInterface;
use Univeros\Polaris\Exception\AuthorizationException;

use function array_fill_keys;
use function is_string;

/**
 * The programmatic authorization check (`docs/auth/rbac.md` §5b): given an authenticated token,
 * does the caller hold the required permission(s) in their active org?
 *
 * It resolves the caller's effective permissions for the token's `org` via {@see PermissionResolver}
 * (so the system `superadmin` override applies automatically) and tests the requirement against
 * them. The {@see \Univeros\Polaris\Http\Middleware\AuthorizationMiddleware} uses {@see allows()} for
 * the declarative edge check; domain services use {@see authorize()} for row-level / conditional
 * checks. Policy callbacks for rules permissions alone cannot express (e.g. last-owner protection)
 * are attached by the domains that own those invariants.
 */
final readonly class Gate
{
    public function __construct(private PermissionResolver $permissions)
    {
    }

    /**
     * @throws AuthorizationException when the caller lacks any of the required permissions
     */
    public function authorize(TokenInterface $token, string ...$permissions): void
    {
        if (!$this->allows($token, ...$permissions)) {
            throw new AuthorizationException('You do not have permission to perform this action.');
        }
    }

    public function allows(TokenInterface $token, string ...$permissions): bool
    {
        return $this->allowsAuthority($this->authority($token), ...$permissions);
    }

    /**
     * The caller's database-resolved authority for their active org. The middleware attaches it
     * to the request so downstream guards never have to trust token claims for role decisions.
     */
    public function authority(TokenInterface $token): ResolvedAuthority
    {
        $organization = $token->getMetadata('org');

        return $this->permissions->resolve(
            (string) $token->getMetadata('sub'),
            is_string($organization) ? $organization : null,
        );
    }

    public function allowsAuthority(ResolvedAuthority $authority, string ...$permissions): bool
    {
        $granted = array_fill_keys($authority->scope, true);
        foreach ($permissions as $permission) {
            if (!isset($granted[$permission])) {
                return false;
            }
        }

        return true;
    }
}
