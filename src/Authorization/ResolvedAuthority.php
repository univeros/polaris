<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

/**
 * A user's effective authority within one active organization, as resolved by
 * {@see PermissionResolver}: the role slugs they hold and the flattened permission keys those
 * roles grant. Immutable.
 */
final readonly class ResolvedAuthority
{
    /**
     * @param list<string> $roles role slugs (e.g. `owner`; or `superadmin` for the global override)
     * @param list<string> $scope permission keys (e.g. `members.invite`)
     */
    public function __construct(
        public array $roles,
        public array $scope,
    ) {
    }
}
