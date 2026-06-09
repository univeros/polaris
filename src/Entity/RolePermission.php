<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;

/**
 * Join row binding a {@see Role} to a {@see Permission} (table `auth_role_permissions`).
 *
 * The composite primary key `(role_id, permission_id)` makes each pairing unique. Both columns are
 * `ON DELETE CASCADE` foreign keys, so deleting a role or a permission removes its grants
 * automatically — there is no such thing as an orphaned grant. Columns use Cycle's abstract types,
 * so the schema is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_role_permissions')]
class RolePermission
{
    #[Column(type: 'string(36)', name: 'role_id', primary: true)]
    public string $roleId = '';

    #[Column(type: 'string(36)', name: 'permission_id', primary: true)]
    public string $permissionId = '';
}
