<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;

/**
 * Join row binding a {@see Membership} to a {@see Role} (table `auth_membership_roles`).
 *
 * This is what grants a user their roles *within a specific organization*. The composite primary
 * key `(membership_id, role_id)` makes each pairing unique. Both columns are `ON DELETE CASCADE`
 * foreign keys, so removing a membership or a role drops the associated grants automatically.
 * Columns use Cycle's abstract types, so the schema is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_membership_roles')]
class MembershipRole
{
    #[Column(type: 'string(36)', name: 'membership_id', primary: true)]
    public string $membershipId = '';

    #[Column(type: 'string(36)', name: 'role_id', primary: true)]
    public string $roleId = '';
}
