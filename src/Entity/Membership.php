<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * Binds one user to one organization (table `auth_memberships`).
 *
 * The `unique(user_id, organization_id)` constraint guarantees a user joins a given organization
 * at most once. A membership starts {@see self::STATUS_INVITED} and becomes {@see self::STATUS_ACTIVE}
 * once accepted (or immediately, for the creator of an organization); {@see $joinedAt} records when.
 * A membership carries the user's org-scoped roles via `auth_membership_roles`. Columns use Cycle's
 * abstract types, so the schema is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_memberships')]
class Membership
{
    /** `status` values. */
    public const string STATUS_INVITED = 'invited';
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_SUSPENDED = 'suspended';

    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    #[Column(type: 'string(36)', name: 'organization_id')]
    public string $organizationId = '';

    /** One of `invited`, `active`, `suspended`. */
    #[Column(type: 'string(16)', name: 'status', default: 'invited')]
    public string $status = 'invited';

    /** The user who issued the invitation, when the membership originated from one. */
    #[Column(type: 'string(36)', name: 'invited_by', nullable: true)]
    public ?string $invitedBy = null;

    /** When the membership became active; null while still invited. */
    #[Column(type: 'datetime', name: 'joined_at', nullable: true)]
    public ?DateTimeImmutable $joinedAt = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;

    #[Column(type: 'datetime', name: 'updated_at')]
    public DateTimeImmutable $updatedAt;
}
