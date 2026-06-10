<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * One append-only security audit record (table `auth_audit_log`).
 *
 * Rows mirror the PSR-14 domain events (`docs/auth/events.md`): the event name, the acting user
 * and org context where known, the client network context, and a JSON {@see $metadata} blob of
 * event-specific identifiers — **never secrets** (tokens, codes, hashes are excluded by the
 * whitelist in {@see \Univeros\Polaris\Observability\AuditLogListener}). Rows are written once and
 * never updated or deleted by the module; retention/archival is host policy
 * (`docs/auth/data-model.md` §3). Columns use Cycle's abstract types, so the schema is portable
 * across every supported driver.
 */
#[Entity(table: 'auth_audit_log')]
class AuditLogEntry
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    /** The acting user; null for anonymous attempts. */
    #[Column(type: 'string(36)', name: 'actor_user_id', nullable: true)]
    public ?string $actorUserId = null;

    #[Column(type: 'string(36)', name: 'organization_id', nullable: true)]
    public ?string $organizationId = null;

    /** The PSR-14 event name, e.g. `user.logged_in`. */
    #[Column(type: 'string(80)', name: 'event')]
    public string $event = '';

    #[Column(type: 'string(45)', name: 'ip', nullable: true)]
    public ?string $ip = null;

    #[Column(type: 'string(255)', name: 'user_agent', nullable: true)]
    public ?string $userAgent = null;

    /** JSON-encoded event-specific identifiers; never secrets. */
    #[Column(type: 'json', name: 'metadata')]
    public string $metadata = '{}';

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;
}
