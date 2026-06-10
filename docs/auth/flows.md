# Authentication Flows

This document specifies the core authentication flows. MFA-specific flows
(TOTP/SMS/email OTP, recovery, step-up) live in [mfa-otp.md](mfa-otp.md); the
endpoint contracts are in [api-reference.md](api-reference.md).

All flows obey two cross-cutting rules:

- **No user enumeration.** Endpoints that take an email (register, login, forgot
  password, resend verification) return an identical generic response whether or
  not the account exists. Differences are surfaced only over authenticated
  channels.
- **Rate limited.** Every unauthenticated mutating endpoint is wrapped by the
  framework `RateLimitMiddleware` keyed by both IP and (where known) account.
  See [security.md](security.md#rate-limiting).

---

## 1. Registration

```
Client                       Polaris
  │  POST /auth/register       │
  │  {email, password,         │
  │   display_name?}           │
  ├───────────────────────────►│ 1. Validate input (Input DTO rules)
  │                            │ 2. Normalize email (lowercase/trim)
  │                            │ 3. Enforce password policy + breach check
  │                            │ 4. If email exists → still return 202 generic
  │                            │ 5. Create user (status=active,
  │                            │    email_verified_at=null,
  │                            │    password_hash=argon2id)
  │                            │ 6. Create email-verification challenge
  │                            │ 7. Emit user.registered → mailer sends OTP/link
  │  202 Accepted (generic)    │
  │◄───────────────────────────┤
```

- **Password policy** is enforced *before* hashing: min length (default 12), not
  in the breached-password set (optional `BreachedPasswordCheckInterface`, e.g.
  HIBP k-anonymity; default no-op). Returns `422` with a problem detail listing
  failed rules; this is *not* enumeration (it's about the submitted password).
- **Hashing:** `password_hash($pw, PASSWORD_ARGON2ID)` via a
  `PasswordHasherInterface` port so the algorithm/cost is configurable and
  swappable. Verification uses `password_verify` (matches the framework's
  `RepositoryIdentityValidator`) and **rehashes on login** when
  `password_needs_rehash()` reports an outdated cost.
- Registration does **not** create an organization. Org creation is a separate,
  authenticated step (or an invitation acceptance); see [rbac.md](rbac.md).
- An unverified user may log in (configurable: `flows.require_verified_email`),
  but until verified receives a token whose `email_verified` claim is `false`;
  the host can gate features on it. Default: **verification required** before
  the first full login → login returns `403 email_unverified` with a resend hint.

---

## 2. Email verification

Two interchangeable styles (config `flows.email_verification.style`):

- **`link`** (default): the email contains `…/verify-email?token=<opaque>`. The
  client posts the token to `POST /auth/email/verify`. The token is the raw
  random value; only its HMAC hash is stored (`auth_email_verifications`).
- **`otp`**: the email contains a 6-digit code; the client posts `{email, code}`.
  Backed by `auth_otp_challenges` (`purpose=email_verify`).

On success: set `email_verified_at`, consume the challenge, emit
`user.email_verified`. Idempotent: re-verifying an already-verified email
returns `200` without error.

`POST /auth/email/verify/resend` always returns `202` generic; internally it
rate-limits per account and reissues a challenge only if the email is unverified.

---

## 3. Login

```
Client                         Polaris
  │  POST /auth/login            │
  │  {email, password}           │
  ├──────────────────────────────►│ 1. Lookup user by normalized email
  │                              │ 2. Constant-time password_verify
  │                              │    (run a dummy verify when user missing,
  │                              │     to equalize timing, anti-enumeration)
  │                              │ 3. Check status (disabled/locked) + lockout
  │                              │ 4. On failure: increment failed_login_count,
  │                              │    maybe lock, emit user.login_failed → 401
  │                              │ 5. On success: reset failed count,
  │                              │    rehash if needed, emit user.logged_in
  │                              │ 6. MFA gate (see below)
```

**MFA gate:**

- If the user has **no confirmed MFA factors** and MFA is not enforced → issue a
  full token pair (step 7 below).
- If the user **has** confirmed factors (or `mfa_enforced`/global enforce) →
  respond `200` with an `mfa_required` body: a short-lived **`mfa_token`** JWT
  (`purpose=login_mfa`, ~5 min) plus the list of available factors (masked
  destinations). The client then completes MFA via `/auth/mfa/challenge` +
  `/auth/mfa/verify` (see [mfa-otp.md](mfa-otp.md)). Only on successful MFA does
  Polaris mint the real token pair.

**Token issuance (step 7), on full success:**

1. Determine **active org**: the user's last-used org, else their only org, else
   `null` (no org context yet). Carried as the `org` claim.
2. Resolve roles/permissions for that org (see [rbac.md](rbac.md)).
3. Mint **access JWT** (`LcobucciTokenGenerator`); claims in §6.
4. Mint **refresh token**: 256-bit CSPRNG opaque secret; store its HMAC hash in
   `auth_refresh_tokens` with a fresh `family_id`, the active org, device UA/IP,
   and `expires_at = now + refresh_ttl`.
5. Return both. The refresh token's plaintext is returned **once** and never
   stored server-side.

Response body:

```json
{
  "data": {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_token": "<opaque>",
    "user": { "id": "…", "email": "…", "email_verified": true },
    "active_org": { "id": "…", "slug": "…", "roles": ["owner"] }
  }
}
```

> **Delivery options.** By default tokens are returned in the JSON body for
> Bearer-header use (no CSRF surface). A host may opt into
> `flows.token_delivery: cookie`, which sets the refresh token as a
> `HttpOnly; Secure; SameSite=Strict` cookie and engages the framework
> `CsrfMiddleware` for cookie-authenticated mutations. The access token stays a
> short-lived bearer value. See [security.md](security.md#token-transport).

---

## 4. Authenticated request validation

Protected routes sit behind the framework's `TokenAuthenticationMiddleware`,
wired with Polaris's `TokenFactory`/`TokenParser`/`TokenValidator`:

1. `HeaderTokenExtractor` pulls the `Authorization: Bearer <jwt>`.
2. Polaris's `TokenParser` (wrapping `LcobucciTokenParser`) verifies signature
   (against the configured public key / JWKS by `kid`), `exp`, `nbf`, `iss`,
   `aud`.
3. The validated `TokenInterface` is attached to the request
   (`TokenInterface::TOKEN_KEY`). Its metadata exposes `sub`, `org`, `roles`,
   `mfa`, `auth_time`, `jti`, `sid`.
4. Authorization (permission checks) runs in a separate `AuthorizationMiddleware`
   downstream; see [rbac.md](rbac.md#enforcement).

Access-token validation is **stateless** (no DB hit) for throughput. Revocation
is handled at the refresh boundary (short access TTL bounds the blast radius);
hosts needing instant access-token kill can enable an optional `jti` denylist
cache (`security.access_token.denylist: true`).

---

## 5. Token refresh & rotation

```
Client                         Polaris
  │  POST /auth/token/refresh    │
  │  {refresh_token}             │
  ├──────────────────────────────►│ 1. HMAC-hash → lookup auth_refresh_tokens
  │                              │ 2. Not found        → 401 invalid_grant
  │                              │ 3. Found & revoked  → REUSE DETECTED:
  │                              │      revoke whole family_id,
  │                              │      emit auth.refresh_reuse_detected → 401
  │                              │ 4. Found & expired  → 401 invalid_grant
  │                              │ 5. Valid: revoke current (reason=rotated),
  │                              │      mint new refresh in SAME family_id with
  │                              │      parent_id=current.id,
  │                              │      mint new access JWT,
  │                              │      emit auth.token_refreshed
  │  200 {access, refresh}       │
  │◄──────────────────────────────┤
```

- **Rotation:** every refresh consumes the presented token and issues a new one
  in the same family. A leaked-then-used old token is detected at step 3.
- **Sliding vs absolute:** refresh lifetime is **absolute** by default
  (`expires_at` fixed at login). Optional sliding mode
  (`refresh_token.sliding: true`) extends `expires_at` on each rotation up to a
  hard cap (`refresh_token.max_lifetime`).
- The new access token re-resolves roles/permissions, so permission changes take
  effect within one access-TTL window without forcing re-login.

---

## 6. Access-token claims

Minted by `LcobucciTokenGenerator` (asymmetric, RS256 or EdDSA):

| Claim          | Meaning                                                      |
| -------------- | ----------------------------------------------------------- |
| `iss`          | configured issuer                                           |
| `aud`          | configured audience (resource servers)                      |
| `sub`          | user id (uuid)                                              |
| `iat` / `exp`  | issued-at / expiry (TTL default 900s)                       |
| `nbf`          | not-before                                                  |
| `jti`          | unique token id (for optional denylist / audit correlation) |
| `sid`          | session = refresh `family_id` (ties access to a device)     |
| `org`          | active organization id (nullable)                          |
| `roles`        | role slugs in the active org, e.g. `["admin"]`             |
| `scope`        | flattened permission keys (optional; off by default to keep tokens small) |
| `email_verified` | bool                                                     |
| `mfa`          | bool; whether this session satisfied MFA                   |
| `amr`          | auth methods, e.g. `["pwd","otp"]`                         |
| `auth_time`    | unix ts of the last full authentication (for step-up)     |

Header carries `kid` for key rotation; verifiers fetch the matching public key
from the JWKS endpoint.

---

## 7. Sessions & logout

- `GET /auth/sessions`: lists the user's active (non-revoked, non-expired)
  refresh tokens as devices: id, masked UA, IP, `created_at`, `last_used_at`,
  and `current: true` for the calling session (matched by `sid`).
- `DELETE /auth/sessions/{id}`: revoke a specific session
  (`revoked_reason=admin`/user); the device's next refresh fails.
- `POST /auth/logout`: revoke the **current** session (by `sid`/refresh).
  Stateless access tokens remain valid until `exp`; enable the `jti` denylist for
  immediate cutoff.
- `POST /auth/logout-all`: revoke every session for the user (e.g. after a
  security scare). Emits `auth.sessions_revoked`.

---

## 8. Password reset (forgot) & change

**Forgot (unauthenticated):**

```
POST /auth/password/forgot {email}
  → 202 generic (always)
  → if user exists & active: create reset challenge (1h TTL),
    emit user.password_reset_requested → mailer sends link/OTP
```

**Reset (with token/OTP):**

```
POST /auth/password/reset {token | (email,code), new_password}
  → validate challenge (unconsumed, unexpired, attempts ok)
  → enforce password policy + breach check
  → set new password_hash, consume challenge
  → revoke ALL refresh tokens (reason=password_change)  ← logout everywhere
  → emit user.password_changed
  → 200
```

**Change (authenticated, step-up required):**

```
POST /auth/password/change {current_password, new_password}
  → require recent MFA/step-up if the user has MFA (auth_time freshness)
  → verify current_password
  → enforce policy, set new hash
  → revoke all OTHER sessions (keep current), reason=password_change
  → emit user.password_changed
```

Resetting/changing a password **always** invalidates other sessions, a core
account-takeover containment measure.

---

## 9. Org switching

A user in multiple orgs operates in one **active org** at a time (the `org`
claim). `POST /auth/switch-org {organization_id}`:

1. Verify the user has an `active` membership in the target org → else `403`.
2. Re-resolve roles/permissions for that org.
3. Mint a **new access token** scoped to the new org. The refresh token's
   `organization_id` is updated to keep subsequent refreshes scoped correctly.
4. Emit `auth.org_switched`.

Returns a fresh access token (and refresh if rotated). The client swaps its
bearer token and continues.

---

## 10. Account status & lockout

- `status=disabled` (admin action) → all auth attempts return `403`; existing
  sessions are revoked.
- **Lockout:** after `lockout.max_attempts` failed logins within
  `lockout.window`, set `locked_until = now + lockout.lock_duration` and
  `status=locked`; emit `user.locked`. Locked logins return a generic `401`
  (no "your account is locked" leak unless authenticated). Auto-unlocks when
  `locked_until` passes; a successful login resets the counter.
- Lockout is **per-account**; IP-based throttling (separate, via rate limiter)
  defends the broader surface so a single attacker can't lock many accounts as a
  DoS; see [security.md](security.md#account-lockout-vs-dos).
