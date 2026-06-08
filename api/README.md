# `api/` — Endpoint specs (source of truth)

These YAML files are the **executable** counterpart of [`docs/auth/`](../docs/auth/).
Each describes one endpoint; `bin/altair spec:scaffold api/<resource>/<action>.yaml`
emits the Action, Input DTO, Responder, Domain stub, test, route entry, and
OpenAPI fragment. Treat the YAML as the source of truth — re-scaffold rather than
hand-editing generated files (see `.ai/skills/altair/SKILL.md`).

```bash
bin/altair spec:scaffold api/auth/login.yaml --dry-run   # preview
bin/altair spec:scaffold api/auth/login.yaml             # emit
bin/altair spec:lint                                     # drift check
```

## What's here

This is the **seed set** — the trickiest/most illustrative endpoints, written as
worked examples:

| Spec                          | Endpoint                       | Illustrates                         |
| ----------------------------- | ------------------------------ | ----------------------------------- |
| `auth/register.yaml`          | `POST /auth/register`          | input rules, persistence, queue side-effect |
| `auth/login.yaml`             | `POST /auth/login`             | dual response (tokens vs mfa)       |
| `auth/token-refresh.yaml`     | `POST /auth/token/refresh`     | rotation + reuse detection          |
| `auth/password/forgot.yaml`   | `POST /auth/password/forgot`   | anti-enumeration generic 202        |
| `auth/password/reset.yaml`    | `POST /auth/password/reset`    | one-of input + logout-everywhere    |
| `auth/mfa/totp-enroll.yaml`   | `POST /auth/mfa/totp/enroll`   | authenticated, QR output            |
| `auth/mfa/challenge.yaml`     | `POST /auth/mfa/challenge`     | OTP send via ports                  |
| `orgs/create.yaml`            | `POST /orgs`                   | multi-tenant write + permission     |

The remaining endpoints in [`docs/auth/api-reference.md`](../docs/auth/api-reference.md)
follow the identical pattern and are added the same way.

## ⚠️ Schema note

The exact key vocabulary for `spec:scaffold` lives in the **host framework**, not
in this module's vendored packages, so the structure below is modeled on the
Altair skill's description (endpoint + input + output + domain, with optional
`persistence:` and `queue:` blocks). Before scaffolding for real, confirm the
schema against a host example:

```bash
bin/altair spec:show api/auth/login.yaml      # validate this file parses
bin/altair spec:scaffold api/... --dry-run    # preview without writing
```

Adjust key names to match `spec:lint` if the host schema differs; the *intent*
(routes, inputs, validation, outputs, domain target, persistence) is what these
files capture.
