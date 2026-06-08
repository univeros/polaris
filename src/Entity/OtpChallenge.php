<?php

declare(strict_types=1);

namespace Univeros\Polaris\Entity;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use DateTimeImmutable;

/**
 * A transient one-time-password challenge (table `auth_otp_challenges`): the SMS/email code sent
 * for a login MFA step, enrollment, step-up, or an OTP-style email-verify / password-reset.
 *
 * The numeric code is never stored — only its keyed HMAC ({@see $codeHash}); for `totp` factors
 * the code is verified live against the factor secret, so {@see $codeHash} is null. A challenge is
 * single-use ({@see $consumedAt}), time-boxed ({@see $expiresAt}), and brute-force-bounded
 * ({@see $attempts} / {@see $maxAttempts}). The short-lived `mfa_token` returned by login is a
 * signed JWT, not a row here — this row holds the actual code. Columns use Cycle's abstract types
 * for driver portability.
 *
 * See `docs/auth/data-model.md` and `docs/auth/mfa-otp.md`.
 */
#[Entity(table: 'auth_otp_challenges')]
class OtpChallenge
{
    /** `purpose` values. */
    public const string PURPOSE_LOGIN_MFA = 'login_mfa';
    public const string PURPOSE_ENROLL = 'enroll';
    public const string PURPOSE_PASSWORD_RESET = 'password_reset';
    public const string PURPOSE_EMAIL_VERIFY = 'email_verify';
    public const string PURPOSE_STEP_UP = 'step_up';

    /** `channel` values. */
    public const string CHANNEL_SMS = 'sms';
    public const string CHANNEL_EMAIL = 'email';
    public const string CHANNEL_TOTP = 'totp';

    /** Default number of verify tries before a challenge is exhausted. */
    public const int DEFAULT_MAX_ATTEMPTS = 5;

    #[Column(type: 'string(36)', name: 'id', primary: true)]
    public string $id = '';

    #[Column(type: 'string(36)', name: 'user_id')]
    public string $userId = '';

    #[Column(type: 'string(36)', name: 'factor_id', nullable: true)]
    public ?string $factorId = null;

    /** One of `login_mfa`, `enroll`, `password_reset`, `email_verify`, `step_up`. */
    #[Column(type: 'string(20)', name: 'purpose')]
    public string $purpose = '';

    /** One of `sms`, `email`, `totp`. */
    #[Column(type: 'string(16)', name: 'channel')]
    public string $channel = '';

    /** Keyed HMAC-SHA256 (hex) of the numeric code; null for `totp` (verified live). */
    #[Column(type: 'string(64)', name: 'code_hash', nullable: true)]
    public ?string $codeHash = null;

    #[Column(type: 'string(320)', name: 'destination', nullable: true)]
    public ?string $destination = null;

    #[Column(type: 'integer', name: 'attempts', default: 0)]
    public int $attempts = 0;

    #[Column(type: 'integer', name: 'max_attempts', default: self::DEFAULT_MAX_ATTEMPTS)]
    public int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS;

    #[Column(type: 'datetime', name: 'expires_at')]
    public DateTimeImmutable $expiresAt;

    #[Column(type: 'datetime', name: 'consumed_at', nullable: true)]
    public ?DateTimeImmutable $consumedAt = null;

    #[Column(type: 'string(45)', name: 'ip', nullable: true)]
    public ?string $ip = null;

    #[Column(type: 'datetime', name: 'created_at')]
    public DateTimeImmutable $createdAt;
}
