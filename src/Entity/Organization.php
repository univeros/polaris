<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A tenant in the multi-tenant model (table `auth_organizations`).
 *
 * Every organization is created by a user — {@see $createdBy} — who becomes its owner via an
 * active {@see Membership} granted the org-scoped `owner` role. The {@see $slug} is unique and
 * URL-safe, derived from the name when not supplied. Columns use Cycle's abstract types, so the
 * schema renders correctly on every supported driver; the UUID v7 primary key is assigned by the
 * application, never auto-incremented, keeping identifiers opaque and tenant size unguessable.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_organizations')]
class Organization
{
    /** `status` values. */
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_SUSPENDED = 'suspended';

    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(160)', name: 'name')]
    public string $name = '';

    /** URL-safe, unique within the deployment. */
    #[Column(type: 'string(160)', name: 'slug')]
    public string $slug = '';

    /** One of `active`, `suspended`. */
    #[Column(type: 'string(16)', name: 'status', default: 'active')]
    public string $status = 'active';

    /** The user who created the organization; becomes its owner. */
    #[Column(type: 'string(36)', name: 'created_by')]
    public string $createdBy = '';

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;

    #[Column(type: 'datetime', name: 'updated_at')]
    public DateTimeImmutable $updatedAt;
}
