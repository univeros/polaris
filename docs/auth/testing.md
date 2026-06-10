# Testing & Acceptance Criteria

Polaris is security-critical; the bar is **≥ 80% coverage** across unit,
integration, and a small E2E layer, with TDD (write the failing test first) per
the project testing rules. Tests double as documentation; the framework's
manifests surface a "tests as documentation" list per package.

## 1. Test pyramid

### Unit (fast, no DB)

Pure domain logic and crypto, with ports mocked:

- **Password:** policy validation, Argon2id hash/verify, `needs_rehash` path.
- **Token minting:** claim assembly, TTL/exp, `mfa_token`/`step_up` purpose
  isolation; signature verifies with the public key, fails with a wrong key.
- **Refresh rotation logic:** new-token-same-family, parent linkage, expiry math,
  sliding cap.
- **Reuse detection:** presenting a revoked token returns the "revoke family"
  decision.
- **OTP:** code generation entropy, HMAC hashing, constant-time compare,
  attempts/expiry state machine, resend cooldown.
- **TOTP:** known-answer vectors (RFC 6238 test vectors), window tolerance,
  replay-within-window rejection.
- **PermissionResolver:** role→permission union, superadmin override, empty-org
  case.
- **Gate/policies:** last-owner protection, admin-can't-edit-owner, grant-only-
  what-you-have.
- **Input DTOs:** every `rules()` set (required/format/length/enum/E.164).

### Integration (real container + SQLite/Postgres + migrations)

Boot the module into a test container, run migrations, exercise services and
HTTP actions end to end against a real DB:

- **Module wiring** (extends the existing `ModuleTest`): routes contributed,
  bindings resolve, entity + migration dirs exist, middleware list correct.
- **Registration → verify → login** happy path; unverified-login gate.
- **Login → MFA required → challenge → verify → tokens** for TOTP, SMS, email,
  and recovery code.
- **Refresh rotation** + **reuse detection** revokes the family (assert all
  family rows revoked + event emitted).
- **Password reset** invalidates all sessions; **change** keeps current session.
- **Org lifecycle**: create→owner, invite→accept→membership, role assignment,
  last-owner removal blocked, cross-tenant access denied.
- **AuthorizationMiddleware**: `perm:*` enforcement returns 403; step-up returns
  401 `step_up_required`; org-path mismatch denied.
- **JWKS** endpoint serves the public key; a token signed by the private key
  verifies against it.
- **Anti-enumeration**: register/login/forgot return identical bodies for
  existing vs non-existing accounts.

### E2E (HTTP, black-box)

A handful of full journeys through the host front controller (framework E2E
harness):

1. Sign up → verify email → log in → enroll TOTP (scan QR data) → log out →
   log in with MFA → access a protected route.
2. Forgot password → reset → old sessions rejected → new login works.
3. Create org → invite teammate → teammate accepts → teammate hits a
   permission-gated route (allowed/denied by role).

## 2. Security-focused tests (must-pass gates)

- Brute-force: N+1 failed logins triggers lockout; lockout auto-expires.
- Rate limits return `429` + `Retry-After` on each protected endpoint group.
- OTP brute force: exhausting attempts burns the challenge.
- OTP bombing: per-destination send cap enforced.
- No secret ever appears in a response body or log (assert against
  serialized output): passwords, refresh tokens, OTP codes, TOTP secrets
  (post-confirm), recovery codes (post-issue).
- Constant-time compare used for all code/token verification (no early return).
- Timing: login response time for missing vs wrong-password is within tolerance.
- Tokens: expired/altered/wrong-aud/wrong-iss/`purpose`-mismatch all rejected.

## 3. Test infrastructure

- **Fixtures/factories** for User, Organization, Membership, Role, MfaFactor with
  sensible defaults (`tests/Factory/*`).
- **Fakes** for ports: `InMemorySmsSender` / `InMemoryOtpMailer` capture sent
  codes so tests can complete OTP flows; `FrozenClock` (lcobucci/clock) for
  deterministic TTL/TOTP/expiry assertions; in-memory `IdentityProvider`.
- **DB:** SQLite in-memory for speed in CI plus a Postgres job for dialect
  fidelity (Cycle supports both); migrations run per suite.
- Run via `vendor/bin/phpunit`; gates via `composer qa` (cs + stan + test) and
  `bin/altair doctor` (incl. the determinism gate).

## 4. Coverage targets

| Layer                         | Target |
| ----------------------------- | ------ |
| Domain services + crypto      | ≥ 95%  |
| Input DTOs / rules            | 100%   |
| HTTP actions/responders       | ≥ 85%  |
| Overall module                | ≥ 80%  |

PHPUnit `source` is already scoped to `src/` (see `phpunit.xml.dist`).

## 5. Acceptance criteria (definition of done)

The module is "done" when **all** hold:

- [ ] All endpoints in [api-reference.md](api-reference.md) implemented and
      covered by functional tests. (The `api/*.yaml` seeds and `spec:lint` are
      host-framework scaffolding tooling; the implemented contracts are the
      source of truth.)
- [ ] Migrations apply cleanly forward and roll back
      (`db:migrate` / `db:migrate:rollback`); `db:migrate:status` green.
- [ ] Coverage ≥ targets above; `composer qa` green; `bin/altair doctor` green.
- [ ] Every item on the [security checklist](security.md#11-pre-implementation-security-checklist)
      satisfied; `security-reviewer` agent run with no CRITICAL/HIGH open.
- [ ] TOTP verified against RFC 6238 vectors; SMS + email OTP verified via fake
      senders; QR provisioning URI parses in a real authenticator app (manual
      smoke).
- [ ] Refresh reuse detection demonstrably revokes the family + emits the event.
- [ ] Multi-tenant isolation proven: a token for org A cannot act on org B.
- [ ] No secret leaks in responses/logs (automated assertion).
- [ ] `code-reviewer` agent run; CRITICAL/HIGH addressed.
- [ ] README + these docs updated to match the shipped surface
      (`bin/altair manifest:generate` regenerated, no drift).
