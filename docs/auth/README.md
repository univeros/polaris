# Polaris — Auth & User Management Module Specification

> `univeros/polaris` — the drop-in authentication, MFA/OTP, and user/organization
> management module for any [Univeros](https://univeros.io) / Altair host app.

Polaris is a **pluggable Univeros module**. A host registers one class in
`config/modules.php` and gains a complete, production-grade identity stack:
registration, email-verified login, JWT access tokens with rotating refresh
tokens, multi-factor authentication (TOTP/QR, SMS OTP, email OTP), multi-tenant
RBAC, and self-service account management — contributed as routes, Cycle
entities, migrations, middleware, and container bindings with **no further host
wiring**.

This directory is the **authoritative specification**. It is written to be
implemented through the Altair spec-driven workflow (`bin/altair spec:scaffold`),
not hand-coded. Implementation has not started — these docs define *what* to
build and *why* before any code is written.

---

## 1. Goals & non-goals

### Goals

- **Self-contained & portable.** Ships everything a host needs to authenticate
  users out of the box; depends only on the Univeros framework contracts and a
  small, audited set of crypto/OTP libraries.
- **Secure by default.** Argon2id password hashing, asymmetric JWT signing,
  hashed-at-rest refresh tokens and OTP codes, rotation with theft detection,
  rate limiting, account lockout, audit logging, and no user enumeration.
- **Multi-tenant.** First-class organizations, memberships, and per-org roles so
  one user can belong to many orgs with different permissions in each.
- **MFA-first.** TOTP authenticator apps (provisioned via QR), SMS OTP, and email
  OTP, plus single-use recovery codes and step-up authentication.
- **Framework-native.** Implements the existing `Altair\Http` auth contracts
  (`IdentityProviderInterface`, `TokenFactoryInterface`, …) rather than inventing
  parallel machinery, and is operated entirely through `bin/altair`.

### Non-goals (v1)

- Social / OAuth2 *client* login (Google, GitHub). Designed-for via a pluggable
  `IdentityLinkInterface`, but no concrete providers ship in v1.
- Acting as a full OAuth2 / OIDC **provider** for third parties. (A JWKS endpoint
  is included so resource servers can verify our tokens; full OIDC is future
  work — see [implementation-plan.md](implementation-plan.md).)
- WebAuthn / passkeys (planned v2; the MFA factor model is built to absorb it).
- A UI. Polaris is a headless JSON API; hosts bring their own frontend.

---

## 2. How it plugs into the framework

Polaris's `Module` class implements the standard provider contracts, so the host
gets everything by registering it once:

| Capability        | Provider interface                          | What Polaris contributes                         |
| ----------------- | ------------------------------------------- | ------------------------------------------------ |
| Service bindings  | `ModuleInterface::apply()`                  | Auth contracts → concrete impls, config, factories |
| HTTP routes       | `RoutesProviderInterface`                   | `/auth/*`, `/users/*`, `/orgs/*`, JWKS           |
| Cycle entities    | `EntityDirectoriesProviderInterface`        | `src/Entity/*` (users, orgs, tokens, factors …)  |
| Migrations        | `MigrationDirectoriesProviderInterface`     | `database/migrations/*`                           |
| PSR-15 middleware | `MiddlewareProviderInterface`               | authentication + authorization + rate-limit guards |

The module **implements the `Altair\Http` contracts** rather than replacing
them. The integration seams are:

- `IdentityProviderInterface` → `CycleIdentityProvider` (looks up users by email).
- `IdentityValidatorInterface` → framework's `RepositoryIdentityValidator`
  (configured with `['username' => 'email', 'hash' => 'password_hash']`), used by
  the framework's `TokenAuthenticationMiddleware` / `BasicAuthenticationMiddleware`.
- `TokenGeneratorInterface` → framework's `LcobucciTokenGenerator` (asymmetric JWT).
- `TokenFactoryInterface` / `TokenParserInterface` / `TokenValidatorInterface` →
  Polaris implementations that mint access JWTs from credentials and validate
  bearer tokens on protected routes.
- `TokenConfigurationInterface` → driven by Polaris module config (issuer,
  audience, TTL, signer, keys).

> Because the contracts already exist in `univeros/http`, Polaris is mostly
> *entities + domain services + a thin set of new contracts* (refresh tokens,
> OTP, RBAC) wired through these seams.

---

## 3. Architecture at a glance

Every endpoint follows the framework's **Action → Input → Domain → Responder**
shape (see `src/Http/...` skeleton). Layering:

```
HTTP edge      Action (route target)  ── thin, declares input/responder/domain
               Input  (readonly DTO)  ── typed request + validation rules()
               Responder              ── marshals Payload → JSON / Problem+JSON
Domain         *Service classes       ── business logic, transactional, emit events
               Contracts/*Interface   ── ports (repos, OTP senders, hashers, clock)
Persistence    Entity/* (Cycle)       ── annotated entities → ORM schema
               Repository/*           ── Cycle-backed repositories (RepositoryInterface)
Security       crypto, hashing, token machinery (impls of Altair\Http contracts)
```

Design rules (inherited from the project coding standards):

- **Immutable DTOs.** Inputs, tokens, and value objects are `readonly`; services
  return new objects, never mutate inputs.
- **Small, focused files.** One class per file, 200–400 lines typical.
- **Ports & adapters.** SMS, email, password hashing, the clock, and the
  breached-password check are all interfaces the host can rebind.
- **Validate at the boundary.** All external input is validated in the Input DTO
  before it reaches a domain service.
- **Never trust, never leak.** Generic responses on auth failures; secrets and
  tokens are hashed/encrypted at rest; constant-time comparisons throughout.

---

## 4. Specification index

Read in this order:

1. **[data-model.md](data-model.md)** — entities, tables, columns, relationships,
   indexes, and the migration set.
2. **[flows.md](flows.md)** — registration, email verification, login, refresh
   rotation, sessions/devices, logout, password reset/change, org switching.
3. **[mfa-otp.md](mfa-otp.md)** — TOTP (QR enrollment), SMS OTP, email OTP,
   recovery codes, MFA-on-login, and step-up authentication.
4. **[rbac.md](rbac.md)** — organizations, memberships, roles, permissions,
   invitations, and the authorization guard.
5. **[api-reference.md](api-reference.md)** — the complete endpoint catalog with
   request/response shapes, auth requirements, and error codes.
6. **[security.md](security.md)** — threat model, cryptography, key management,
   rate limiting, lockout, and compliance considerations.
7. **[configuration.md](configuration.md)** — module config schema, environment
   variables, container bindings, and dependencies to add.
8. **[events.md](events.md)** — the PSR-14 domain events Polaris emits.
9. **[testing.md](testing.md)** — test strategy, fixtures, and acceptance criteria.
10. **[implementation-plan.md](implementation-plan.md)** — phased build order,
    composer changes, and the `spec:scaffold` command sequence.

The executable counterpart of this spec lives in [`api/`](../../api/) — the YAML
endpoint specs that `bin/altair spec:scaffold` turns into Action/Input/Responder/
Domain/test/OpenAPI/route artifacts.

---

## 5. Conventions used in this spec

- **Identifiers:** UUID v7 (time-ordered) primary keys everywhere, surfaced as
  strings. Never expose sequential integers.
- **Tables:** prefixed `auth_` to avoid collisions with host tables.
- **Timestamps:** UTC, stored as `datetime`, named `*_at`.
- **Secrets at rest:** TOTP secrets are **encrypted** (`Altair\Security\Encrypter`);
  refresh tokens, OTP codes, reset/verification tokens, and recovery codes are
  stored only as **HMAC-SHA256 hashes** (with a server pepper) — never plaintext.
- **API envelope:** success → `{ "data": … }`; error → RFC 9457 Problem Details
  (`application/problem+json`) with a stable `type`/`code`. See
  [api-reference.md](api-reference.md#error-format).
- **Naming:** permission keys are `resource.action` (e.g. `members.invite`);
  role slugs are lowercase (`owner`, `admin`, `member`).
