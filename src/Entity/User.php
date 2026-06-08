<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * The identity record behind {@see \Univeros\Polaris\Module} (table `auth_users`).
 *
 * Columns use Cycle's abstract types, so the schema renders correctly on every
 * supported driver (PostgreSQL, MySQL, SQL Server, …) — nothing here is
 * database-specific. The UUID v7 primary key is assigned by the application
 * (never auto-incremented), so identifiers stay opaque and portable.
 *
 * See `docs/auth/data-model.md` for the full field reference.
 */
#[Entity(table: 'auth_users')]
class User
{
    /** `status` values. */
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_DISABLED = 'disabled';
    public const string STATUS_LOCKED = 'locked';

    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(320)', name: 'email')]
    public string $email = '';

    #[Column(type: 'datetime', name: 'email_verified_at', nullable: true)]
    public ?DateTimeImmutable $emailVerifiedAt = null;

    #[Column(type: 'string(255)', name: 'password_hash', nullable: true)]
    public ?string $passwordHash = null;

    #[Column(type: 'string(120)', name: 'display_name', nullable: true)]
    public ?string $displayName = null;

    /** One of `active`, `disabled`, `locked`. */
    #[Column(type: 'string(16)', name: 'status', default: 'active')]
    public string $status = 'active';

    #[Column(type: 'boolean', name: 'mfa_enforced', default: false)]
    public bool $mfaEnforced = false;

    #[Column(type: 'integer', name: 'failed_login_count', default: 0)]
    public int $failedLoginCount = 0;

    #[Column(type: 'datetime', name: 'locked_until', nullable: true)]
    public ?DateTimeImmutable $lockedUntil = null;

    #[Column(type: 'datetime', name: 'last_login_at', nullable: true)]
    public ?DateTimeImmutable $lastLoginAt = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;

    #[Column(type: 'datetime', name: 'updated_at')]
    public DateTimeImmutable $updatedAt;
}
