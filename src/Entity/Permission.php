<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;

/**
 * A single, fine-grained capability in the permission catalog (table `auth_permissions`).
 *
 * Permissions are the atoms of authorization — e.g. `members.invite`, `roles.manage` — referenced
 * by {@see $key} ({@see $key} is unique). The catalog is the single source of truth seeded from a
 * code-defined registry on migrate (see #30); roles aggregate permissions via `auth_role_permissions`.
 * This is a static reference table, so it carries no timestamps. Columns use Cycle's abstract types,
 * so the schema is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_permissions')]
class Permission
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    /** Stable, unique catalog key, e.g. `members.invite`. */
    #[Column(type: 'string(120)', name: 'key')]
    public string $key = '';

    #[Column(type: 'string(255)', name: 'description')]
    public string $description = '';
}
