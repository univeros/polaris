# Implementation Plan

How to build Polaris from this spec, in dependency order, using the Altair
spec-driven workflow. **No code has been written yet** — this is the build
sequence. Each phase ends green (`composer qa` + `bin/altair doctor`) before the
next begins.

> **Golden rule (from the Altair skill):** you do **not** hand-write the
> Action/Input/Responder/Domain/test/route/OpenAPI quad. Write a YAML spec under
> `api/`, run `bin/altair spec:scaffold`, then fill in the generated domain stub.
> Entities + repositories + migrations come from the spec's `persistence:` block
> (or `db:migration-plan`). Hand-editing generated files causes drift that
> `spec:lint` / `doctor` will flag.

---

## Phase 0 — Project hygiene

1. Fix `composer.json` name/namespace/deps (see
   [configuration.md](configuration.md#composerjson-fix-required)):
   `univeros/polaris`, `Univeros\Polaris\` autoload, add `univeros/security`,
   `spomky-labs/otphp`, `endroid/qr-code`, `symfony/uid`.
2. `composer update`; confirm autoload + `vendor/bin/phpunit` still green.
3. Remove the skeleton sample (`SampleEntity`, `SampleService`, `SampleAction`,
   `SampleInput`, `SampleResponder`, the sample migration) **after** Phase 1
   replaces `ModuleTest`'s assertions.
4. Establish `AuthConfig` value object + boot-time validation of required env
   (`APP_KEY`, JWT keys).

**Exit:** module boots, config + secrets validated, CI green on an empty surface.

---

## Phase 1 — Identity core (register, verify, login, tokens)

Foundational; everything else depends on users + tokens.

- **Entities/migrations:** `auth_users`, `auth_refresh_tokens`,
  `auth_email_verifications`, `auth_password_resets`.
- **Ports & crypto:** `PasswordHasherInterface` (Argon2id),
  `CycleIdentityProvider`, HMAC pepper helper (HKDF), `PolarisTokenFactory` /
  `TokenValidator` / `TokenParser`, `TokenConfiguration` from `AuthConfig`.
- **Services:** `RegistrationService`, `LoginService` (no-MFA path),
  `TokenService` (mint/rotate/refresh + reuse detection), `PasswordService`.
- **Endpoints (scaffold from `api/`):** `register`, `email/verify`,
  `email/verify/resend`, `login`, `token/refresh`, `logout`, `logout-all`,
  `me`, `sessions` (list/revoke), `password/forgot`, `password/reset`,
  `password/change`, JWKS.
- **Middleware:** wire `TokenAuthenticationMiddleware` + `AuthRateLimitMiddleware`
  with auth rules for public paths.
- **Tests:** unit (tokens, rotation, reuse, password) + integration (full
  register→verify→login→refresh).

**Exit:** a user can register, verify, log in, refresh with rotation, and log
out; reuse detection works; anti-enumeration verified.

---

## Phase 2 — MFA & OTP

Layer MFA onto login + step-up. (User-prioritized: SMS, TOTP/QR, email.)

- **Entities/migrations:** `auth_mfa_factors`, `auth_otp_challenges`,
  `auth_recovery_codes`.
- **Ports:** `SmsSenderInterface`, `OtpMailerInterface` (+ `Log*`/`Null*`
  drivers), `TotpProviderInterface` (otphp), `QrCodeRendererInterface` (endroid),
  `BreachedPasswordCheckInterface` (null default).
- **Services:** `MfaService` (enroll/confirm/list/remove), `OtpService`
  (challenge/verify/recovery), step-up issuance; extend `LoginService` with the
  MFA gate + `mfa_token`.
- **Endpoints (scaffold):** `mfa/factors`, `mfa/totp/{enroll,confirm}`,
  `mfa/sms/{enroll,confirm}`, `mfa/email/{enroll,confirm}`, `mfa/challenge`,
  `mfa/verify`, `mfa/step-up`, `mfa/recovery-codes/regenerate`,
  `mfa/factors/{id}` (patch/delete).
- **Tests:** RFC 6238 vectors for TOTP, fake senders for SMS/email OTP, recovery
  codes, step-up enforcement, OTP brute-force/bombing limits.

**Exit:** all three OTP channels + recovery codes work end to end; QR provisions
a real authenticator app; step-up gates sensitive ops.

---

## Phase 3 — Multi-tenant RBAC

Organizations, memberships, roles, permissions, authorization.

- **Entities/migrations:** `auth_organizations`, `auth_memberships`,
  `auth_roles`, `auth_permissions`, `auth_role_permissions`,
  `auth_membership_roles`, `auth_invitations`; the seed migration for the
  permission catalog + system role templates.
- **Services:** `OrganizationService`, `MembershipService`, `RoleService`,
  `PermissionResolver`, `Gate` (+ policies); extend `TokenService` to embed
  `org`/`roles` and re-resolve on refresh/switch.
- **Middleware:** `AuthorizationMiddleware` (permission + step-up + org-scope
  checks from Action declarations).
- **Endpoints (scaffold):** `orgs` CRUD, `switch-org`, members
  (list/roles/remove), invites (create/list/revoke/accept), roles CRUD,
  `permissions` catalog, users (read/update/disable/enable/delete).
- **Tests:** privilege-escalation guards, last-owner protection, cross-tenant
  isolation, permission enforcement matrix.

**Exit:** full multi-tenant authorization; a token for org A cannot act on org B;
invitations work.

---

## Phase 4 — Hardening, observability, ops

- `AuditLogListener` + `NotificationListener` (PSR-14) → `auth_audit_log` + ports.
- `PruneExpiredService` maintenance command for transient-row cleanup.
- Optional `jti` denylist cache for instant access revocation.
- Optional sliding refresh; HIBP breach-check adapter behind the existing port.
- Observability spans/metrics on auth paths; alert events documented.
- **Key rotation runbook:** publish new `kid` in JWKS → switch active signing
  key → retire old key after one access-TTL window.
- Final `security-reviewer` + `code-reviewer` passes; satisfy the full
  acceptance checklist in [testing.md](testing.md#5-acceptance-criteria-definition-of-done).

**Exit:** production-ready, audited, observable, documented.

---

## Optional adapters

Shipped as a **separate** package `univeros/polaris-adapters` so core stays
dependency-light:

- `TwilioSmsSender` (implements `SmsSenderInterface`).
- `SymfonyMailerOtpAdapter` / SES adapter (implements `OtpMailerInterface`).
- `HibpBreachedPasswordCheck` (implements `BreachedPasswordCheckInterface`).

Hosts `composer require univeros/polaris-adapters` and bind them; core works with
the `Log*` drivers in dev without any of these.

---

## Future work (post-v1)

- **WebAuthn / passkeys** as a fourth `auth_mfa_factors` type (model already
  accommodates it) — likely strongest factor, enables passwordless.
- **Social / OIDC client login** via `IdentityLinkInterface` (Google, GitHub,
  Apple) linking to existing users.
- **Full OIDC provider** mode (authorization-code + PKCE) so Polaris can be an
  IdP for third parties, building on the existing JWKS endpoint.
- **SCIM** provisioning for enterprise directory sync.
- **Risk-based / adaptive MFA** (new device / impossible-travel signals driving
  step-up).

---

## Scaffold command sequence (per endpoint)

```bash
# 1. write the YAML spec (see api/ for the seed set)
$EDITOR api/auth/login.yaml

# 2. preview, then emit the Action/Input/Responder/Domain/test/route/OpenAPI
bin/altair spec:scaffold api/auth/login.yaml --dry-run
bin/altair spec:scaffold api/auth/login.yaml

# 3. implement the generated domain stub (the only hand-written logic)

# 4. for entities/migrations from a persistence: block or schema diff
bin/altair db:migration-plan         # safety-checked migration
bin/altair db:migrate

# 5. guard against drift + verify
bin/altair spec:lint
composer qa && bin/altair doctor
```

The seed YAML specs in [`api/`](../../api/) cover the trickiest endpoints
(register, login, refresh, TOTP enroll, MFA challenge, org create) as worked
examples; the remaining endpoints in [api-reference.md](api-reference.md) follow
the identical pattern.
