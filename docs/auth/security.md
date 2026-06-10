# Security & Threat Model

Polaris is a security-critical module; this document is the reference for *why*
each control exists and how it's configured. It maps controls to concrete
threats and to OWASP ASVS / Top-10 categories.

---

## 1. Cryptography

| Concern               | Choice                                                                 |
| --------------------- | --------------------------------------------------------------------- |
| Password hashing      | **Argon2id** via `password_hash`/`password_verify` (PHP 8.5 + sodium); `password_needs_rehash` on login |
| Access-token signing  | **Asymmetric** JWT — RS256 (default) or EdDSA (Ed25519). Private key signs, public key verifies (JWKS) |
| Refresh tokens        | 256-bit CSPRNG opaque secret; stored as **HMAC-SHA256(secret, pepper)** |
| OTP / reset / verify codes | CSPRNG; stored as **HMAC-SHA256(code, pepper)**; constant-time `hash_equals` |
| TOTP shared secret    | 160-bit; **encrypted at rest** with `Altair\Security\Encrypter` (AES-256-CBC + HMAC) |
| Pepper / app key      | Derived from the app key via **HKDF** (`Altair\Security\Support\HkdfKey`), separate context per use (`refresh`, `otp`, `recovery`) |
| Randomness            | `random_bytes` / `random_int` only — never `mt_rand`/`uniqid`         |

**Why asymmetric JWT?** Resource servers (other Univeros services) verify tokens
with the **public** key and can never mint them. The signing key lives only in
the auth service. The framework's `LcobucciTokenGenerator` already implements
asymmetric signing — Polaris configures it.

**Secrets never stored in plaintext.** Anything that could replay an
authentication (refresh tokens, OTP codes, reset/verify/invite tokens, recovery
codes) is stored only as a keyed hash. TOTP secrets, which *must* be recoverable
to verify, are encrypted (reversible) rather than hashed.

---

## 2. Key management & rotation

- **App key** (`APP_KEY`) seeds HKDF-derived peppers for HMAC and the
  `Encrypter` key. Required at boot — the module **fails fast** if missing
  (validated in `Module::apply()`), per the project security rules.
- **JWT keypair**: private (`AUTH_JWT_PRIVATE_KEY`) + public
  (`AUTH_JWT_PUBLIC_KEY`), PEM, provided via env / secret manager — never
  committed. Each key has a `kid`.
- **Rotation:** multiple public keys may be published at once at
  `/auth/.well-known/jwks.json`; new tokens are signed with the current `kid`,
  old tokens stay verifiable until their (short) TTL lapses. Rotate by adding the
  new key, switching the active `kid`, then retiring the old key after one
  access-TTL window. Documented as an ops runbook in
  [implementation-plan.md](implementation-plan.md).
- **Pepper rotation** requires re-hashing on next use (refresh tokens naturally
  rotate; OTPs are short-lived) — documented but rarely needed.

---

## 3. Token security

- **Short access TTL (15 min default)** bounds the damage of a leaked access
  token without a per-request DB lookup.
- **Refresh rotation + reuse detection** (see [flows.md](flows.md#token-refresh--rotation)):
  a replayed (already-rotated) refresh token revokes its entire family and emits
  `auth.refresh_reuse_detected` → the host can alert/force re-login. This detects
  refresh-token theft.
- **Token transport:**
  - *Default* — access + refresh returned in JSON; client stores access in memory
    and refresh in secure storage; sends `Authorization: Bearer`. No CSRF surface.
  - *Cookie mode* (`flows.token_delivery: cookie`) — refresh in
    `HttpOnly; Secure; SameSite=Strict` cookie; the framework `CsrfMiddleware`
    guards cookie-authenticated mutations. Mitigates XSS token theft at the cost
    of CSRF handling.
- **`mfa_token` / `step_up`** are single-purpose JWTs; the auth middleware
  rejects them on normal routes by checking the `purpose` claim.
- **Optional `jti` denylist** (`security.access_token.denylist`) for hosts
  needing instant access-token revocation (logout-everywhere takes effect
  immediately) — a small cache lookup per request.
- **Audience/issuer pinning**: tokens carry and are validated against configured
  `iss`/`aud`, so a token for service A isn't accepted by service B.

---

## 4. Anti-enumeration

User-existence must not leak. Enforced at:

- `register`, `login`, `password/forgot`, `email/verify/resend` → identical
  generic responses regardless of account existence.
- `login` runs a **dummy `password_verify`** against a fixed hash when the user
  is missing, equalizing response timing.
- `404 not_found` is returned (instead of `403`) for resources the caller may
  not even know exist, where appropriate.

---

## 5. Rate limiting

Built on the framework `RateLimitMiddleware` + `IpKeyResolver`, plus
account-scoped keys. Per-endpoint defaults (config `rate_limits`, all tunable):

| Endpoint group               | Key(s)                    | Default budget            |
| ---------------------------- | ------------------------- | ------------------------- |
| `login`                      | IP + email                | 10 / 5 min per key        |
| `register`                   | IP                        | 5 / hour                  |
| `password/forgot`            | IP + email                | 5 / hour                  |
| `mfa/challenge`, OTP sends   | IP + account + destination| 5 / 10 min, 30s cooldown  |
| `mfa/verify`                 | account + `mfa_token`     | 5 / challenge, 20 / hour  |
| `token/refresh`              | IP + family               | 60 / min                  |
| global authenticated         | user id                   | 600 / min                 |

Responses set `X-RateLimit-*` and `429` returns `Retry-After`. OTP-send limits
include a **per-destination** key to prevent OTP-bombing a victim's phone/email.

---

## 6. Account lockout vs. DoS

- **Per-account lockout** after N failed logins (default 5 / 15 min →
  15 min lock, then auto-unlock). Stops online password guessing.
- **Risk:** naive per-account lockout lets an attacker lock victims out by
  failing their logins (a DoS). Mitigations:
  - IP-based rate limiting absorbs distributed guessing *before* lockout triggers.
  - Lockout is time-boxed (auto-unlock), not permanent.
  - Successful auth from a known device/session can be exempted from the counter
    (config `lockout.trust_known_devices`).
  - Lockout state is **not** revealed to anonymous callers (generic `401`).

---

## 7. Input validation & injection

- All external input validated in readonly **Input DTOs** with `rules()` before
  reaching domain code (framework `InputParser` + rules). Email normalized;
  phone forced to E.164; enums whitelisted.
- **SQL injection:** all persistence via Cycle ORM / parameterized queries — no
  string-built SQL.
- **Mass assignment:** Inputs are explicit allow-lists of typed properties; no
  blind hydration of request bodies into entities.
- **Output:** JSON responses; no HTML rendering, so XSS surface is the host's UI,
  not Polaris. Tokens/secrets are never echoed except the one-time issuance.

---

## 8. Audit & monitoring

- Security events ([events.md](events.md)) are persisted append-only to
  `auth_audit_log` via a PSR-14 listener, with actor, org, IP, UA, and non-secret
  metadata.
- Every domain event also increments the `polaris.auth.events` counter
  (`MetricsListener`, via `univeros/observability`) with the catalog name as the
  `event` attribute, so alert rules are simple attribute filters.
- High-signal alerts to configure (filter the counter, or the audit log):
  any `auth.refresh_reuse_detected` (token theft indicator); spikes of
  `user.login_failed`, `user.locked`, `mfa.verify_failed` or
  `mfa.otp_verify_failed` (credential stuffing / brute force);
  `mfa.recovery_used` (sign-in without the primary factor);
  `member.roles_changed` and `role.*` anomalies (privilege changes);
  `user.disabled`, `user.deleted` and `org.deleted` (destructive admin actions).
- The framework observability layer (`observability:tail`/`stats`) surfaces auth
  span latencies and error rates via its request middleware; OTLP export is
  available. Polaris contributes the domain-level counter above.

---

## 9. Privacy & compliance

- **PII minimization:** Polaris stores email, optional display name, optional
  phone (for SMS factor). No unnecessary profile data.
- **Right to erasure:** `DELETE /users/{id}` anonymizes the user (hash email,
  null name/phone, revoke sessions) while preserving referential integrity of
  audit rows (actor replaced with a tombstone id).
- **Data at rest:** secrets hashed/encrypted as above; DB-level encryption is a
  host/infra concern.
- **Transport:** TLS assumed end-to-end; `Secure` cookies require HTTPS;
  the module refuses to set auth cookies over plaintext (checks request scheme,
  mirroring `BasicAuthenticationMiddleware::checkAllowance`).
- **Retention:** transient tokens pruned (see
  [data-model.md](data-model.md#3-retention--cleanup)); audit retained per host
  policy (default 1 year).

---

## 10. Threat → control matrix

| Threat                                   | Primary control(s)                                                   |
| ---------------------------------------- | ------------------------------------------------------------------- |
| Credential stuffing / brute force        | rate limiting, lockout, breached-password check, MFA                 |
| Phishing / password reuse                | MFA (TOTP/SMS/email), step-up on sensitive ops                      |
| Token theft (access)                     | short TTL, audience pinning, optional `jti` denylist, cookie mode   |
| Token theft (refresh)                    | rotation + **reuse detection** (revoke family), hashed at rest      |
| User enumeration                         | generic responses, timing equalization                              |
| OTP brute force                          | 6-digit + 5 attempts + 5-min expiry + per-account verify limit      |
| OTP bombing (cost/abuse)                 | per-destination send limits + resend cooldown                       |
| Privilege escalation                     | can't grant roles you lack; last-owner & hierarchy policies; org-scope checks |
| Cross-tenant access                      | path-org vs token-org consistency check; superadmin explicit        |
| Account takeover via reset               | hashed single-use tokens, 1h expiry, **logout-all on reset**         |
| Session fixation                         | new tokens minted on every auth; refresh rotates                    |
| Replay (TOTP within window)              | last-accepted step tracking per factor                              |
| Key compromise                           | asymmetric signing, key rotation via `kid`/JWKS, fail-fast on missing keys |
| Insider/abuse                            | append-only audit log, alertable events                             |

---

## 11. Pre-implementation security checklist

Mirrors the project security rules — to be satisfied before the module is
considered done (tracked in [testing.md](testing.md)):

- [ ] No hardcoded secrets; `APP_KEY` + JWT keys from env, validated at boot.
- [ ] All inputs validated in Input DTOs.
- [ ] Parameterized queries only (Cycle ORM).
- [ ] CSRF guarded in cookie mode.
- [ ] AuthN + AuthZ verified on every non-public route.
- [ ] Rate limiting on every unauthenticated mutating endpoint.
- [ ] Error messages leak nothing sensitive (generic + Problem Details).
- [ ] Secrets hashed/encrypted at rest; constant-time comparisons.
- [ ] Security review (`security-reviewer` agent) before first release.
