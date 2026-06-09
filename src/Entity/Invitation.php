<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A pending invitation for someone to join an organization (table `auth_invitations`).
 *
 * The invitee is identified by {@see $email} and may not yet be a registered user. The emailed
 * invite token is never stored — only its keyed HMAC-SHA256 in {@see $tokenHash} ({@see $tokenHash}
 * is unique), mirroring how email-verification / password-reset tokens are handled. {@see $roleIds}
 * holds a JSON-encoded array of role ids to grant when the invitation is accepted; it is encoded and
 * decoded by the invitation service, keeping this entity a thin row mirror. An invitation is single
 * use: {@see $acceptedAt} is set on acceptance, and it is only valid until {@see $expiresAt}.
 * Columns use Cycle's abstract types, so the schema is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
#[Entity(table: 'auth_invitations')]
class Invitation
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'organization_id')]
    public string $organizationId = '';

    /** Invitee address; may not yet belong to a registered user. */
    #[Column(type: 'string(320)', name: 'email')]
    public string $email = '';

    /** JSON-encoded array of role ids to grant on acceptance; encoded/decoded by the service. */
    #[Column(type: 'json', name: 'role_ids')]
    public string $roleIds = '[]';

    /** Keyed HMAC-SHA256 (hex) of the emailed invite token; never the token itself. */
    #[Column(type: 'string(64)', name: 'token_hash')]
    public string $tokenHash = '';

    #[Column(type: 'string(36)', name: 'invited_by')]
    public string $invitedBy = '';

    #[Column(type: 'datetime', name: 'expires_at')]
    public DateTimeImmutable $expiresAt;

    #[Column(type: 'datetime', name: 'accepted_at', nullable: true)]
    public ?DateTimeImmutable $acceptedAt = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;
}
