<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A registered multi-factor authenticator for a user (table `auth_mfa_factors`).
 *
 * A factor only satisfies MFA once {@see $confirmedAt} is set — enrollment creates an
 * unconfirmed factor that a verify step confirms. TOTP factors keep their shared secret
 * {@see $secretEncrypted} **encrypted** (reversible, via the framework `Encrypter`), since it
 * must be recoverable to verify codes; SMS/email factors carry a destination instead and verify
 * against a per-challenge {@see OtpChallenge}. Columns use Cycle's abstract types, so the schema
 * is portable across every supported driver.
 *
 * See `docs/auth/data-model.md` and `docs/auth/mfa-otp.md`.
 */
#[Entity(table: 'auth_mfa_factors')]
class MfaFactor
{
    /** `type` values. */
    public const string TYPE_TOTP = 'totp';
    public const string TYPE_SMS = 'sms';
    public const string TYPE_EMAIL = 'email';

    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    /** One of `totp`, `sms`, `email`. */
    #[Column(type: 'string(16)', name: 'type')]
    public string $type = '';

    #[Column(type: 'string(80)', name: 'label', nullable: true)]
    public ?string $label = null;

    /** TOTP shared secret, encrypted (never stored in plaintext); null for sms/email factors. */
    #[Column(type: 'text', name: 'secret_encrypted', nullable: true)]
    public ?string $secretEncrypted = null;

    #[Column(type: 'string(20)', name: 'phone_e164', nullable: true)]
    public ?string $phoneE164 = null;

    #[Column(type: 'string(320)', name: 'email', nullable: true)]
    public ?string $email = null;

    #[Column(type: 'boolean', name: 'is_default', default: false)]
    public bool $isDefault = false;

    #[Column(type: 'datetime', name: 'confirmed_at', nullable: true)]
    public ?DateTimeImmutable $confirmedAt = null;

    #[Column(type: 'datetime', name: 'last_used_at', nullable: true)]
    public ?DateTimeImmutable $lastUsedAt = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;

    #[Column(type: 'datetime', name: 'updated_at')]
    public DateTimeImmutable $updatedAt;
}
