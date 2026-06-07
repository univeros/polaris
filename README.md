# Polaris

> **Authentication, MFA & user management for the [Univeros](https://univeros.io) framework.**
> One line in `config/modules.php` — a complete, production-grade identity stack.

![PHP](https://img.shields.io/badge/PHP-8.3%2B-777BB4?logo=php&logoColor=white)
![Univeros module](https://img.shields.io/badge/Univeros-module-1d76db)
![Multi-tenant](https://img.shields.io/badge/multi--tenant-RBAC-0052cc)
![MFA](https://img.shields.io/badge/MFA-TOTP%20%C2%B7%20SMS%20%C2%B7%20email-d93f0b)
![Status](https://img.shields.io/badge/status-in%20development-orange)

Polaris is the official **authentication & user-management module** for Univeros /
Altair applications. A host registers one class and the app gains email-verified
login, JWT access tokens with **rotating refresh tokens**, **multi-factor
authentication** (TOTP/QR, SMS, email), single-use recovery codes, **multi-tenant
organizations with role-based access control**, and a hardened security
posture — contributed as routes, Cycle entities, migrations, and middleware with
**no further host wiring**.

The name is the idea: *Polaris* is the fixed star your application's identity
navigates by.

---

## Why Polaris

- **🔌 Drop-in.** Implements the standard Univeros module contracts. Register it,
  run migrations, done — no per-module bootstrapping.
- **🔐 Secure by default.** Argon2id passwords, asymmetric JWT signing, refresh
  tokens & OTP codes hashed at rest, rotation with theft detection, rate limiting,
  lockout, audit logging, and no user enumeration.
- **🏢 Multi-tenant.** First-class organizations, memberships, and per-org roles —
  one user, many orgs, different permissions in each.
- **📱 MFA-first.** TOTP authenticator apps (provisioned by QR), SMS OTP, and email
  OTP, plus recovery codes and step-up authentication for sensitive actions.
- **🧩 Framework-native.** Builds on the existing `Altair\Http` auth contracts
  (`TokenGeneratorInterface`, `IdentityProviderInterface`, …) instead of inventing
  parallel machinery, and is operated entirely through `bin/altair`.
- **📦 Dependency-light & portable.** SMS and email delivery are pluggable ports —
  no vendor SDK is baked into the core.

---

## Features

| Area | What you get |
| --- | --- |
| **Authentication** | Register, email verification, password login, `/auth/me`, logout / logout-all |
| **Tokens** | Asymmetric JWT access tokens (RS256/EdDSA) + opaque **rotating refresh tokens** with reuse detection; JWKS endpoint |
| **Sessions** | Per-device session list, individual + global revocation |
| **MFA / OTP** | **TOTP (QR)**, **SMS OTP**, **email OTP**, recovery codes, login-MFA gate, step-up |
| **Passwords** | Argon2id, policy enforcement, breached-password hook, reset & change (logout-everywhere) |
| **Multi-tenant RBAC** | Organizations, memberships, roles, permissions, invitations, org switching |
| **Authorization** | Declarative permission guard middleware + a programmatic `Gate` with policies |
| **Security** | Rate limiting, account lockout, anti-enumeration, audit log, key rotation |
| **Ops** | PSR-14 domain events, notification fan-out, transient-row pruning, observability |

---

## Quick start

```bash
composer require univeros/polaris
```

```php
// config/modules.php
return [
    new Univeros\Polaris\Module(),
];
```

Provide the secrets (env / secret manager):

```bash
export APP_KEY="…"                              # 32-byte base64
export AUTH_JWT_PRIVATE_KEY="$(cat private.pem)" # signs access tokens
export AUTH_JWT_PUBLIC_KEY="$(cat public.pem)"   # verification / JWKS
```

Apply the migrations and verify:

```bash
bin/altair db:migrate
bin/altair routes:list --format=json | grep auth
bin/altair doctor
```

That single registration contributes every `/auth`, `/users`, and `/orgs` route,
the entities, the migrations, the auth/authorization middleware, and the container
bindings. Bind production SMS/email providers in your host container when you're
ready — Polaris ships dev (log) drivers so flows work out of the box.

---

## How it works

Every endpoint follows the framework's **Action → Input → Domain → Responder**
shape, and Polaris plugs into the framework's existing auth seams rather than
replacing them:

```
HTTP edge   Action            thin route target — declares input/responder/domain + required permissions
            Input (readonly)  typed request DTO with validation rules()
            Responder         Payload → JSON / RFC 9457 Problem Details
Domain      *Service          business logic, transactional, emits PSR-14 events
            Contracts/*       ports: SmsSender, OtpMailer, PasswordHasher, Clock, …
Persistence Entity/* (Cycle)  UUID-v7 entities → host ORM schema
Security    token machinery   implements Altair\Http\Contracts\* (TokenFactory, IdentityProvider, …)
```

Login returns a short-lived **JWT access token** plus a **rotating refresh
token**; presenting an already-rotated refresh token is treated as theft and
revokes the entire token family.

---

## API surface

A representative slice (full catalog in
[`docs/auth/api-reference.md`](docs/auth/api-reference.md)):

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/register` | Create account, send verification |
| `POST` | `/auth/login` | Password login → tokens **or** MFA challenge |
| `POST` | `/auth/token/refresh` | Rotate refresh → new access + refresh |
| `POST` | `/auth/mfa/totp/enroll` | Start TOTP enrollment → secret + QR |
| `POST` | `/auth/mfa/verify` | Complete MFA → tokens |
| `GET`  | `/auth/sessions` | List active devices/sessions |
| `POST` | `/orgs` | Create an organization (creator → owner) |
| `POST` | `/orgs/{id}/invites` | Invite a member |
| `POST` | `/auth/switch-org` | Switch active org → re-scoped token |

> **Versioning & mounting are the host's responsibility.** Polaris contributes
> relative, unversioned routes; the host front controller mounts them under
> whatever scheme (e.g. a `/v1` prefix) it uses for its own surface.

Endpoints are generated from YAML specs under [`api/`](api/) via
`bin/altair spec:scaffold`.

---

## Multi-factor authentication

Three factor types, one uniform verification flow:

- **TOTP (authenticator app)** — RFC 6238 via `spomky-labs/otphp`; enrolled by
  scanning a QR code (`otpauth://` provisioning URI). Secrets are encrypted at
  rest.
- **SMS OTP** — 6-digit codes delivered through your `SmsSenderInterface` binding.
- **Email OTP** — 6-digit codes delivered through your `OtpMailerInterface`
  binding.
- **Recovery codes** — 10 single-use codes, hashed at rest.
- **Step-up** — sensitive operations (password change, removing a factor, deleting
  an org) require a recent strong authentication.

SMS and email delivery are **provider-agnostic ports** — bind Twilio, Vonage, SES,
SMTP, or anything else; dev `Log` drivers ship in the box. Details in
[`docs/auth/mfa-otp.md`](docs/auth/mfa-otp.md).

---

## Multi-tenant RBAC

Identity is global; authority is scoped to an organization:

```
User ──< Membership >── Organization
              └──< roles >── permissions   (per-org; system roles when org is null)
```

Org creators become `owner`; `admin`/`member` templates are seeded per org and
fully customizable. The access token carries the active org and resolved roles, so
authorization is mostly stateless; an `AuthorizationMiddleware` enforces
per-endpoint permissions and a `Gate` handles the rules permissions can't express
(last-owner protection, role hierarchy). Cross-tenant access is denied by design.
See [`docs/auth/rbac.md`](docs/auth/rbac.md).

---

## Security

Polaris follows established standards — **JWT** (RFC 7519), **JWKS** (RFC 7517),
**TOTP** (RFC 6238), **OAuth 2.0 refresh semantics + Security BCP** (RFC 9700),
**Problem Details** (RFC 9457), and **OWASP ASVS** for password storage. Secrets
are never stored in plaintext (hashed or encrypted at rest), comparisons are
constant-time, and signing keys are asymmetric with `kid`-based rotation. Full
threat model in [`docs/auth/security.md`](docs/auth/security.md).

---

## Documentation

The complete, authoritative specification lives in [`docs/auth/`](docs/auth/):

| Doc | Contents |
| --- | --- |
| [README](docs/auth/README.md) | Overview, goals, framework integration |
| [data-model](docs/auth/data-model.md) | Entities, tables, relationships, migrations |
| [flows](docs/auth/flows.md) | Register, login, refresh rotation, sessions, password |
| [mfa-otp](docs/auth/mfa-otp.md) | TOTP/QR, SMS, email, recovery, step-up |
| [rbac](docs/auth/rbac.md) | Orgs, memberships, roles, permissions, guard |
| [api-reference](docs/auth/api-reference.md) | Full endpoint catalog + error format |
| [security](docs/auth/security.md) | Threat model, crypto, key management |
| [configuration](docs/auth/configuration.md) | Config schema, env, bindings, deps |
| [events](docs/auth/events.md) | PSR-14 domain events |
| [testing](docs/auth/testing.md) | Test strategy + acceptance criteria |
| [implementation-plan](docs/auth/implementation-plan.md) | Phased build order |

Agent-oriented orientation is in [`AGENT.md`](AGENT.md).

---

## Roadmap & status

Polaris is in **active development**, built in five phases tracked on GitHub:

| Phase | Milestone |
| --- | --- |
| **0 — Foundation** | identity, config/secrets, deps, CI |
| **1 — Identity core** | register, login, JWT + rotating refresh, sessions |
| **2 — MFA & OTP** | TOTP/QR, SMS, email, recovery, step-up |
| **3 — Multi-tenant RBAC** | orgs, roles, permissions, invitations |
| **4 — Hardening & ops** | audit, observability, key rotation, sign-off |

Progress lives in the [milestones](https://github.com/univeros/polaris/milestones)
and [issues](https://github.com/univeros/polaris/issues); each phase has an `epic`
tracking issue.

---

## Testing

```bash
composer install
vendor/bin/phpunit
```

The target is **≥ 80 % coverage** with unit, integration, and E2E layers, with
TOTP validated against RFC 6238 vectors and OTP channels exercised through
in-memory senders. See [`docs/auth/testing.md`](docs/auth/testing.md).

---

## Contributing

Issues and pull requests are welcome on
[github.com/univeros/polaris](https://github.com/univeros/polaris). Please read
[`AGENT.md`](AGENT.md) and the relevant spec doc first, follow the conventions
(strict types, immutability, small files, tests-first), and run `composer qa`
before opening a PR.

---

## License

Proprietary. © Univeros. See `composer.json`.
