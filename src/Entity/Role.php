<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A named bundle of permissions, scoped to an organization (table `auth_roles`).
 *
 * A role belongs to one organization, or is a **system role** when {@see $organizationId} is null
 * (e.g. the global `superadmin`, or the `owner`/`admin`/`member` templates cloned into each org).
 * {@see $slug} is unique within its organization (`unique(organization_id, slug)`). System roles
 * ({@see $isSystem}) cannot be edited or deleted by tenants. A role's permissions are bound via
 * `auth_role_permissions`; a membership's roles via `auth_membership_roles`. Columns use Cycle's
 * abstract types, so the schema is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_roles')]
class Role
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    /** Owning organization; null marks a system/global role. */
    #[Column(type: 'string(36)', name: 'organization_id', nullable: true)]
    public ?string $organizationId = null;

    #[Column(type: 'string(80)', name: 'name')]
    public string $name = '';

    /** URL-safe; unique within the owning organization. */
    #[Column(type: 'string(80)', name: 'slug')]
    public string $slug = '';

    #[Column(type: 'string(255)', name: 'description', nullable: true)]
    public ?string $description = null;

    /** System roles cannot be deleted or edited by tenants. */
    #[Column(type: 'boolean', name: 'is_system', default: false)]
    public bool $isSystem = false;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;

    #[Column(type: 'datetime', name: 'updated_at')]
    public DateTimeImmutable $updatedAt;
}
