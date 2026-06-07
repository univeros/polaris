<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A single-use password-reset token (table `auth_password_resets`).
 *
 * The emailed token is never stored — only its keyed HMAC-SHA256 hash
 * ({@see \Univeros\Polaris\Security\Pepper}). A row is consumed exactly once
 * (`consumedAt`) and expires after the configured window (default 1h, shorter than
 * verification by design). Columns use Cycle's abstract types, so the schema is
 * portable across every supported driver.
 *
 * Shares its shape with {@see EmailVerification}; see `docs/auth/data-model.md`.
 */
#[Entity(table: 'auth_password_resets')]
class PasswordReset
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    /** The address the reset was requested for. */
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
