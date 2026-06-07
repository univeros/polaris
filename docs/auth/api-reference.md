# API Reference

The complete Polaris endpoint catalog. Every endpoint is a framework
**Action → Input → Domain → Responder** quad, scaffolded from a YAML spec under
[`api/`](../../api/). JSON in, JSON out.

- **Base path & versioning:** none assumed. The module contributes relative,
  unversioned routes; **mounting and API versioning (e.g. a `/v1` prefix, header
  or media-type negotiation) are the host's responsibility**, not the module's.
  Polaris stays version-agnostic so a host can mount it however it versions its
  own surface.
- **Auth column:** `—` public · `Bearer` valid access token · `mfa_token`
  login-MFA ticket · `step-up` recent strong auth · `perm:x` requires permission.
- **Success envelope:** `{ "data": … }`. **Error envelope:** RFC 9457 Problem
  Details (see [§ Error format](#error-format)).

---

## 1. Authentication

| Method | Path                          | Auth        | Purpose                                              |
| ------ | ----------------------------- | ----------- | ---------------------------------------------------- |
| POST   | `/auth/register`              | —           | Create account; sends email verification            |
| POST   | `/auth/login`                 | —           | Password login → tokens **or** `mfa_required`       |
| POST   | `/auth/token/refresh`         | —¹          | Rotate refresh → new access + refresh                |
| POST   | `/auth/logout`                | Bearer      | Revoke current session                              |
| POST   | `/auth/logout-all`            | Bearer      | Revoke all sessions                                 |
| GET    | `/auth/me`                    | Bearer      | Current identity, orgs, roles, MFA status           |
| POST   | `/auth/switch-org`            | Bearer      | Set active org → new scoped access token            |
| GET    | `/auth/sessions`              | Bearer      | List active sessions/devices                        |
| DELETE | `/auth/sessions/{id}`         | Bearer      | Revoke a specific session                           |
| GET    | `/auth/.well-known/jwks.json` | —           | Public keys for verifying access tokens             |

¹ the refresh token itself is the credential (body or HttpOnly cookie).

## 2. Email verification & password

| Method | Path                          | Auth          | Purpose                            |
| ------ | ----------------------------- | ------------- | ---------------------------------- |
| POST   | `/auth/email/verify`          | —             | Verify email (token or email+code) |
| POST   | `/auth/email/verify/resend`   | —             | Resend verification (generic 202)  |
| POST   | `/auth/password/forgot`       | —             | Request reset (generic 202)        |
| POST   | `/auth/password/reset`        | —             | Reset with token/OTP; logout-all   |
| POST   | `/auth/password/change`       | Bearer+step-up| Change while logged in             |

## 3. MFA

| Method | Path                                   | Auth                | Purpose                              |
| ------ | -------------------------------------- | ------------------- | ------------------------------------ |
| GET    | `/auth/mfa/factors`                    | Bearer              | List factors                         |
| POST   | `/auth/mfa/totp/enroll`                | Bearer              | Start TOTP → secret + QR             |
| POST   | `/auth/mfa/totp/confirm`               | Bearer              | Confirm TOTP code                    |
| POST   | `/auth/mfa/sms/enroll`                 | Bearer              | Register phone, send SMS OTP         |
| POST   | `/auth/mfa/sms/confirm`                | Bearer              | Confirm SMS factor                   |
| POST   | `/auth/mfa/email/enroll`               | Bearer              | Register email factor, send OTP      |
| POST   | `/auth/mfa/email/confirm`              | Bearer              | Confirm email factor                 |
| PATCH  | `/auth/mfa/factors/{id}`               | Bearer              | Set label / default                  |
| DELETE | `/auth/mfa/factors/{id}`               | Bearer+step-up      | Remove a factor                      |
| POST   | `/auth/mfa/challenge`                  | mfa_token \| Bearer | Send OTP for a factor (login/step-up)|
| POST   | `/auth/mfa/verify`                     | mfa_token           | Complete login MFA → tokens          |
| POST   | `/auth/mfa/step-up`                    | Bearer              | Re-auth a factor → fresh `auth_time` |
| POST   | `/auth/mfa/recovery-codes/regenerate`  | Bearer+step-up      | New recovery codes (returned once)   |

## 4. Organizations, members, roles

| Method | Path                                       | Auth                | Purpose                       |
| ------ | ------------------------------------------ | ------------------- | ----------------------------- |
| POST   | `/orgs`                                     | Bearer              | Create org (caller → owner)   |
| GET    | `/orgs`                                     | Bearer              | My orgs                       |
| GET    | `/orgs/{id}`                                | Bearer · perm:org.read    | Org detail              |
| PATCH  | `/orgs/{id}`                                | Bearer · perm:org.update  | Update org              |
| DELETE | `/orgs/{id}`                                | Bearer · perm:org.delete · step-up | Delete org     |
| GET    | `/orgs/{id}/members`                         | perm:members.read   | List members                  |
| PATCH  | `/orgs/{id}/members/{userId}/roles`         | perm:members.update | Set a member's roles          |
| DELETE | `/orgs/{id}/members/{userId}`               | perm:members.remove | Remove a member               |
| POST   | `/orgs/{id}/invites`                         | perm:members.invite | Invite by email               |
| GET    | `/orgs/{id}/invites`                         | perm:members.read   | List pending invites          |
| DELETE | `/orgs/{id}/invites/{inviteId}`             | perm:members.invite | Revoke an invite              |
| POST   | `/auth/invites/accept`                       | Bearer              | Accept an invitation          |
| GET    | `/orgs/{id}/roles`                           | perm:roles.read     | List roles                    |
| POST   | `/orgs/{id}/roles`                           | perm:roles.manage   | Create custom role            |
| PATCH  | `/orgs/{id}/roles/{roleId}`                  | perm:roles.manage   | Update role                   |
| DELETE | `/orgs/{id}/roles/{roleId}`                  | perm:roles.manage   | Delete role                   |
| GET    | `/permissions`                               | Bearer              | Permission catalog (UI)       |

## 5. Users (admin / self)

| Method | Path                  | Auth                  | Purpose                         |
| ------ | --------------------- | --------------------- | ------------------------------- |
| GET    | `/users/{id}`         | Bearer (self) · perm:users.read | Read a user           |
| PATCH  | `/users/{id}`         | Bearer (self) · perm:users.manage | Update profile      |
| POST   | `/users/{id}/disable` | perm:users.manage · step-up | Disable (revokes sessions) |
| POST   | `/users/{id}/enable`  | perm:users.manage     | Re-enable                       |
| DELETE | `/users/{id}`         | Bearer (self) · step-up | Delete/anonymize account      |

---

## 6. Representative request/response contracts

Selected endpoints in detail; the rest follow the same conventions. Inputs map
1:1 to readonly Input DTOs with validation `rules()`.

### `POST /auth/register`

Request:
```json
{ "email": "ada@example.com", "password": "correct horse battery staple", "display_name": "Ada" }
```
Rules: `email` required|email|max:320 · `password` required|string|min:12 ·
`display_name` optional|string|max:120.

Response `202 Accepted` (always generic — anti-enumeration):
```json
{ "data": { "status": "verification_sent" } }
```

### `POST /auth/login`

Request: `{ "email": "ada@example.com", "password": "…" }`

Response A — no MFA, `200`:
```json
{ "data": {
  "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 900,
  "refresh_token": "<opaque>",
  "user": { "id": "018f…", "email": "ada@example.com", "email_verified": true },
  "active_org": { "id": "018f…", "slug": "acme", "roles": ["owner"] }
} }
```

Response B — MFA required, `200`:
```json
{ "data": {
  "mfa_required": true,
  "mfa_token": "<jwt purpose=login_mfa>",
  "factors": [
    { "id": "…", "type": "totp", "label": "Authenticator", "default": true },
    { "id": "…", "type": "sms", "destination": "+1 *** *** 0101" }
  ]
} }
```

Errors: `401 invalid_credentials` (generic), `403 email_unverified`,
`429 too_many_requests`.

### `POST /auth/token/refresh`

Request: `{ "refresh_token": "<opaque>" }` (or cookie).
Response `200`: new `access_token` + rotated `refresh_token`.
Errors: `401 invalid_grant` (unknown/expired/**reuse-detected** — all generic).

### `POST /auth/mfa/totp/enroll`

Response `200`:
```json
{ "data": {
  "factor_id": "018f…",
  "secret": "JBSWY3DPEHPK3PXP",
  "otpauth_uri": "otpauth://totp/Acme:ada@example.com?secret=JBSW…&issuer=Acme&digits=6&period=30",
  "qr_svg": "<svg …>…</svg>"
} }
```
`?format=png` → `qr_png_base64` instead of `qr_svg`.

### `POST /auth/mfa/verify`

Auth: `Authorization: Bearer <mfa_token>`.
Request: `{ "factor_id": "018f…", "code": "123456" }`
(or `{ "type": "recovery", "code": "abcde-fghij" }`).
Response `200`: full token pair (same shape as login Response A,
`amr: ["pwd","otp"]`).
Errors: `401 mfa_failed` (attempts remaining decremented), `429`.

### `POST /orgs` / invite / member contracts

`POST /orgs` → `201 { data: { id, name, slug, role: "owner" } }`.
`POST /orgs/{id}/invites` `{ "email": "…", "role_slugs": ["member"] }` →
`201 { data: { invite_id, expires_at } }`.

---

## 7. Error format

All errors use `application/problem+json` (RFC 9457), produced by the framework's
`ProblemDetailsErrorHandler`:

```json
{
  "type": "https://docs.univeros.io/errors/invalid_credentials",
  "title": "Invalid credentials",
  "status": 401,
  "code": "invalid_credentials",
  "detail": "The email or password is incorrect.",
  "instance": "/auth/login",
  "errors": { "password": ["The password is incorrect."] }
}
```

- `code` is a **stable machine string** (clients branch on it, not on `detail`).
- `errors` (optional) is the per-field validation map for `422` responses.
- Security-sensitive failures use deliberately generic `detail` (no enumeration).

### Stable error codes

| HTTP | `code`                  | When                                            |
| ---- | ----------------------- | ----------------------------------------------- |
| 400  | `bad_request`           | malformed body                                  |
| 401  | `invalid_credentials`   | bad login                                       |
| 401  | `invalid_grant`         | bad/expired/reused refresh                      |
| 401  | `invalid_token`         | bad/expired access token                        |
| 401  | `mfa_failed`            | wrong OTP/recovery code                          |
| 401  | `step_up_required`      | sensitive op needs recent MFA                    |
| 403  | `email_unverified`      | verification required before login               |
| 403  | `forbidden`             | authenticated but lacking permission             |
| 403  | `account_disabled`      | disabled/locked account                          |
| 404  | `not_found`             | resource missing (or hidden for privacy)         |
| 409  | `conflict`              | e.g. slug taken, already a member                |
| 422  | `validation_failed`     | input rule violation (`errors` populated)        |
| 429  | `too_many_requests`     | rate limit / lockout (`Retry-After` header)      |

---

## 8. Headers & conventions

- **Auth:** `Authorization: Bearer <access_token>`.
- **Rate limit:** responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Reset`; `429` includes `Retry-After`.
- **Idempotency:** `POST /auth/register`, invites, and OTP sends are safe to
  retry (idempotent-ish, generic responses); destructive ops are not.
- **Pagination:** list endpoints accept `?page` / `?limit` (default 20, max 100)
  and return `{ "data": [...], "meta": { "total", "page", "limit" } }`.
- **Content type:** `application/json`; `Accept` negotiated by the framework
  `FormatNegotiatorMiddleware`.
