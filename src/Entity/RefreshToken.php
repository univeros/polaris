<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A refresh-token session/device record (table `auth_refresh_tokens`).
 *
 * The opaque token is never stored — only its keyed HMAC hash
 * ({@see \Univeros\Polaris\Security\Pepper}). `familyId` ties a rotation lineage
 * together so that replaying a rotated token can revoke the whole family
 * (theft detection). Like every Polaris entity, columns use Cycle's abstract
 * types and are therefore portable across all supported database drivers.
 *
 * See `docs/auth/data-model.md` and `docs/auth/flows.md` for the rotation design.
 */
#[Entity(table: 'auth_refresh_tokens')]
class RefreshToken
{
    /** `revoked_reason` values. */
    public const string REASON_ROTATED = 'rotated';
    public const string REASON_LOGOUT = 'logout';
    public const string REASON_REUSE_DETECTED = 'reuse_detected';
    public const string REASON_ADMIN = 'admin';
    public const string REASON_PASSWORD_CHANGE = 'password_change';

    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    #[Column(type: 'string(36)', name: 'organization_id', nullable: true)]
    public ?string $organizationId = null;

    #[Column(type: 'string(36)', name: 'family_id')]
    public string $familyId = '';

    #[Column(type: 'string(36)', name: 'parent_id', nullable: true)]
    public ?string $parentId = null;

    /** Keyed HMAC-SHA256 (hex) of the opaque token; never the token itself. */
    #[Column(type: 'string(64)', name: 'token_hash')]
    public string $tokenHash = '';

    #[Column(type: 'string(255)', name: 'user_agent', nullable: true)]
    public ?string $userAgent = null;

    #[Column(type: 'string(45)', name: 'ip', nullable: true)]
    public ?string $ip = null;

    /** Whether the session's authentication included a second factor; mirrored into refreshed access tokens (#97). */
    #[Column(type: 'boolean', name: 'mfa', default: false)]
    public bool $mfa = false;

    /** Comma-joined authentication-method references (e.g. `pwd,otp`); null on pre-#97 rows. */
    #[Column(type: 'string(64)', name: 'amr', nullable: true)]
    public ?string $amr = null;

    /** Unix timestamp of the session's last full authentication (login or step-up). */
    #[Column(type: 'integer', name: 'auth_time', nullable: true)]
    public ?int $authTime = null;

    #[Column(type: 'datetime', name: 'expires_at')]
    public DateTimeImmutable $expiresAt;

    #[Column(type: 'datetime', name: 'last_used_at', nullable: true)]
    public ?DateTimeImmutable $lastUsedAt = null;

    #[Column(type: 'datetime', name: 'revoked_at', nullable: true)]
    public ?DateTimeImmutable $revokedAt = null;

    /** One of `rotated`, `logout`, `reuse_detected`, `admin`, `password_change`. */
    #[Column(type: 'string(32)', name: 'revoked_reason', nullable: true)]
    public ?string $revokedReason = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;
}
