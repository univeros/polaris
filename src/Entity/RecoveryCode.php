<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A single-use MFA recovery code (table `auth_recovery_codes`).
 *
 * Codes are issued in batches (10) when a user enables MFA; regenerating invalidates the prior
 * batch. Only the keyed HMAC ({@see $codeHash}) is stored — never the plaintext — and a code is
 * spent by stamping {@see $usedAt}. Columns use Cycle's abstract types for driver portability.
 *
 * See `docs/auth/data-model.md` and `docs/auth/mfa-otp.md`.
 */
#[Entity(table: 'auth_recovery_codes')]
class RecoveryCode
{
    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    /** Keyed HMAC-SHA256 (hex) of the plaintext recovery code; never the code itself. */
    #[Column(type: 'string(64)', name: 'code_hash')]
    public string $codeHash = '';

    #[Column(type: 'datetime', name: 'used_at', nullable: true)]
    public ?DateTimeImmutable $usedAt = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;
}
