# Multi-Factor Authentication & OTP

Polaris ships three MFA factor types plus recovery codes and step-up
authentication. All three are modeled uniformly as **`auth_mfa_factors`** rows
and verified through a single **`auth_otp_challenges`** ticket mechanism, so the
login/step-up flow is identical regardless of channel.

| Factor   | How the code is produced            | How it's delivered          | Stored at rest                |
| -------- | ----------------------------------- | --------------------------- | ----------------------------- |
| **TOTP** | Authenticator app (RFC 6238)        | QR code at enrollment       | shared secret **encrypted**   |
| **SMS**  | Server CSPRNG, 6 digits             | `SmsSenderInterface`        | code **HMAC-hashed**, transient |
| **Email**| Server CSPRNG, 6 digits             | `OtpMailerInterface`        | code **HMAC-hashed**, transient |

Common parameters (config `otp` / `otp.totp` — see [configuration.md](configuration.md)):

- OTP code length: **6** digits (config `otp.length`).
- SMS/email OTP TTL: **300 s**; max attempts: **5**; then the challenge is burned.
- TOTP: 6 digits, 30 s period, **SHA1** (authenticator-app standard), validation
  window **±1** step to tolerate clock skew.
- Codes generated with `random_int()` (CSPRNG). SMS/email codes are stored only
  as `HMAC-SHA256(code, pepper)`; verification is constant-time (`hash_equals`).
- **TOTP replay guard:** the last-accepted TOTP counter (`time-step`) per factor
  is remembered (`last_used_at` mapped to its step) so the same code can't be
  reused inside its 30 s window.

---

## 1. Ports — provider-agnostic delivery

Polaris does **not** bundle Twilio/SES SDKs. It defines ports and ships dev
drivers; the host binds real providers in its container.

```php
namespace Univeros\Polaris\Contracts;

interface SmsSenderInterface
{
    /** @param non-empty-string $toE164  E.164 phone, e.g. +14155550101 */
    public function send(string $toE164, string $message): void;
}

interface OtpMailerInterface
{
    /** @param array<string,mixed> $context  template vars (code, ttl, app name…) */
    public function send(string $toEmail, string $template, array $context): void;
}
```

Shipped drivers:

- `LogSmsSender` / `LogOtpMailer` — write to the framework logger (dev/test;
  the OTP appears in logs so developers can complete flows without a provider).
- `NullSmsSender` / `NullOtpMailer` — no-ops for environments that disable a
  channel.

Host binds production adapters (examples documented, **not shipped**):

```php
// host config/container
$container->singleton(SmsSenderInterface::class, TwilioSmsSender::class);
$container->singleton(OtpMailerInterface::class, SymfonyMailerOtpAdapter::class);
```

> This keeps Polaris dependency-light and portable. The optional "include
> concrete adapters" path (Twilio/SMTP) is documented in
> [implementation-plan.md](implementation-plan.md#optional-adapters) as an add-on
> package `univeros/polaris-adapters`, not part of the core module.

---

## 2. TOTP enrollment (QR code)

```
Client (logged in)                Polaris
  │ POST /auth/mfa/totp/enroll      │
  ├──────────────────────────────────►│ 1. Generate base32 secret (160-bit)
  │                                 │    via spomky-labs/otphp TOTP::generate()
  │                                 │ 2. Create UNCONFIRMED factor
  │                                 │    (secret_encrypted = Encrypter->encrypt)
  │                                 │ 3. Build otpauth:// provisioning URI:
  │                                 │    otpauth://totp/{issuer}:{email}
  │                                 │      ?secret=…&issuer=…&digits=6&period=30
  │                                 │ 4. Render QR (endroid/qr-code) → SVG/PNG
  │ 200 {factor_id, secret,         │
  │      otpauth_uri,               │
  │      qr_svg | qr_png_base64}    │
  │◄──────────────────────────────────┤
  │                                 │
  │ (user scans QR in Authy/Google  │
  │  Authenticator/1Password…)      │
  │                                 │
  │ POST /auth/mfa/totp/confirm     │
  │ {factor_id, code}               │
  ├──────────────────────────────────►│ 5. Decrypt secret, TOTP->verify(code, window=1)
  │                                 │ 6. On success: set confirmed_at,
  │                                 │    if first factor → generate recovery codes,
  │                                 │    emit mfa.enrolled
  │ 200 {recovery_codes?: [...]}    │   (recovery codes returned ONCE)
  │◄──────────────────────────────────┤
```

- The **secret** is returned alongside the QR so users who can't scan can type it
  manually. After `confirm`, it is never returned again.
- The `otpauth://` URI follows the de-facto Key URI Format; `issuer` comes from
  `otp.totp.issuer` (e.g. the host app's brand) so the entry is labeled nicely in
  the authenticator app.
- QR rendering defaults to **SVG** (no GD/Imagick dependency); PNG is available
  (`gd` is present) when the client requests `?format=png`.
- An unconfirmed TOTP factor cannot satisfy MFA and is pruned if never confirmed.

**Library choice:** `spomky-labs/otphp` (mature, RFC-6238/4226 compliant) for
TOTP generate/verify; `endroid/qr-code` for QR rendering. See
[configuration.md](configuration.md#dependencies-to-add).

---

## 3. SMS factor enrollment

```
POST /auth/mfa/sms/enroll {phone_e164}
  → validate E.164, create UNCONFIRMED sms factor
  → create otp_challenge (purpose=enroll, channel=sms, code_hash, 5m)
  → SmsSenderInterface->send(phone, "Your code is 123456")
  → 200 {factor_id, destination: "+1 *** *** 0101"}   (masked)

POST /auth/mfa/sms/confirm {factor_id, code}
  → verify challenge (unconsumed, unexpired, attempts<max, hash_equals)
  → set confirmed_at, consume challenge,
    generate recovery codes if first factor, emit mfa.enrolled
  → 200
```

Phone numbers are validated/normalized to **E.164** at the boundary (a
`PhoneNumberRule`); invalid numbers are rejected `422`. The destination is always
**masked** in responses.

---

## 4. Email factor enrollment

Identical to SMS but `channel=email` and delivered via `OtpMailerInterface`.
Defaults the factor's `email` to the user's verified account email; a different
address must itself be verifiable. Useful as a fallback factor and for users
without a phone.

```
POST /auth/mfa/email/enroll {email?}        → sends 6-digit code, masked dest
POST /auth/mfa/email/confirm {factor_id, code}
```

---

## 5. MFA on login

Continues the login flow from [flows.md](flows.md#3-login). After password
success, when the user has ≥1 confirmed factor (or MFA is enforced):

```
/auth/login → 200 {
  "mfa_required": true,
  "mfa_token": "<short-lived JWT, purpose=login_mfa, ~5m>",
  "factors": [
    {"id":"…","type":"totp","label":"Authenticator","default":true},
    {"id":"…","type":"sms","destination":"+1 *** *** 0101"},
    {"id":"…","type":"email","destination":"a***@example.com"}
  ]
}
```

Then:

```
# For sms/email factors the client first requests a code:
POST /auth/mfa/challenge
  Authorization: Bearer <mfa_token>
  {factor_id}
  → creates otp_challenge (purpose=login_mfa), sends code, returns masked dest
  → (TOTP factors skip this step — code comes from the app)

# Complete MFA:
POST /auth/mfa/verify
  Authorization: Bearer <mfa_token>
  {factor_id, code}
  → TOTP: decrypt secret, verify(window)
  → sms/email: hash_equals against challenge, attempts/expiry enforced
  → recovery: matches an unused recovery code (see §6)
  → on success: emit mfa.verified, mint the REAL access+refresh pair
    (amr=["pwd","otp"], mfa=true, auth_time=now)
  → 200 {access_token, refresh_token, …}   (same shape as normal login)
```

- The `mfa_token` is single-purpose and cannot be used as an access token (its
  `purpose` claim is checked; the auth middleware rejects it on normal routes).
- Failed `verify` attempts increment the challenge's `attempts` and emit
  `mfa.verify_failed`; exhausting attempts burns the challenge and requires a new
  login. Rate-limited per `mfa_token`/account.
- The user may pick any of their factors (factor diversity = resilience).

---

## 6. Recovery codes

- Generated at **first factor confirmation** (and on demand): 10 codes, each
  ~10 chars (base32, grouped `xxxxx-xxxxx`). Returned **once**; stored as HMAC
  hashes (`auth_recovery_codes`).
- Used in place of an OTP at `/auth/mfa/verify` (`factor_id` omitted or
  `type=recovery`): the submitted code is hashed and matched against unused
  rows; a match marks it `used_at` and authenticates. Single-use.
- `POST /auth/mfa/recovery-codes/regenerate` (step-up required) invalidates the
  prior batch and returns a fresh set; emits `mfa.recovery_regenerated`.
- A low-remaining-codes signal (e.g. ≤3 left) is surfaced in `/auth/me` so the
  host can prompt regeneration.

---

## 7. Step-up authentication

Sensitive operations require a **recent** strong authentication, independent of
whether the access token is otherwise valid:

| Operation                                   | Requirement                          |
| ------------------------------------------- | ------------------------------------ |
| Change password (`/auth/password/change`)   | recent step-up if MFA enabled        |
| Remove/disable an MFA factor                | recent step-up                       |
| Regenerate recovery codes                   | recent step-up                       |
| Delete account / transfer org ownership     | recent step-up                       |

"Recent" = `now - auth_time <= security.step_up.max_age` (default 300 s). When
stale, the endpoint returns `401 step_up_required` with a `WWW-Authenticate`-style
problem detail. The client obtains a fresh factor verification via
`POST /auth/mfa/step-up` (challenge + verify with `purpose=step_up`), which
mints a new access token with a refreshed `auth_time` — then retries.

This is enforced by a small `StepUpGuard` the relevant Actions opt into (declared
on the Action, checked by `AuthorizationMiddleware`), not duplicated in each
domain service.

---

## 8. MFA management & enforcement

- `GET /auth/mfa/factors` — list the user's factors (type, label, masked
  destination, confirmed, default).
- `DELETE /auth/mfa/factors/{id}` — remove a factor (step-up). Removing the last
  factor is blocked while MFA is enforced for the user/org.
- `PATCH /auth/mfa/factors/{id}` — set label / default.
- **Enforcement:** `mfa.enforce` (global) and per-user `mfa_enforced` and per-org
  policy. When enforced and the user has no confirmed factor, login still
  succeeds for password but issues an access token flagged `mfa=false` and the
  `AuthorizationMiddleware` restricts the user to enrollment endpoints until a
  factor is confirmed ("grace enrollment"). Configurable to hard-block instead.

---

## 9. Abuse controls specific to OTP

- **Send throttling:** `/auth/mfa/challenge`, `/auth/mfa/sms/enroll`,
  `/auth/mfa/email/enroll` are rate-limited per account *and* per destination to
  cap SMS/email cost and prevent OTP-bombing a victim's phone.
- **Verify throttling:** independent limit on verify attempts; the per-challenge
  `max_attempts` plus a per-account window stop brute force of the 6-digit space.
- **Resend cooldown:** a minimum interval between sends for the same challenge
  (config `otp.resend_cooldown`, default 30 s).
- All OTP send/verify activity is audited (`mfa.*` events → `auth_audit_log`).
