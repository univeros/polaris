<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A single-use email-verification token (table `auth_email_verifications`).
 *
 * The emailed token is never stored — only its keyed HMAC-SHA256 hash
 * ({@see \Univeros\Polaris\Security\Pepper}). A row is consumed exactly once
 * (`consumedAt`) and expires after the configured window (default 24h). Columns use
 * Cycle's abstract types, so the schema is portable across every supported driver.
 *
 * Shares its shape with {@see PasswordReset}; see `docs/auth/data-model.md`.
 */
#[Entity(table: 'auth_email_verifications')]
class EmailVerification
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    /** The address being verified (stored even if the user later changes it). */
    #[Column(type: 'string(320)', name: 'email')]
    public string $email = '';

    /** Keyed HMAC-SHA256 (hex) of the emailed token; never the token itself. */
    #[Column(type: 'string(64)', name: 'token_hash')]
    public string $tokenHash = '';

    #[Column(type: 'datetime', name: 'expires_at')]
    public DateTimeImmutable $expiresAt;

    #[Column(type: 'datetime', name: 'consumed_at', nullable: true)]
    public ?DateTimeImmutable $consumedAt = null;

    #[Column(type: 'string(45)', name: 'ip', nullable: true)]
    public ?string $ip = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;
}
