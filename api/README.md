# `api/`: endpoint specs

One YAML spec per implemented endpoint, regenerated from the shipped code
(Phases 1-4). The human-readable counterpart is
[`docs/auth/api-reference.md`](../docs/auth/api-reference.md); both describe
the same surface, and the code is the source of truth for each. For operating
the module as an agent, see
[`.ai/skills/polaris/SKILL.md`](../.ai/skills/polaris/SKILL.md).

## Layout

| Directory          | Endpoints                                                        |
| ------------------ | ---------------------------------------------------------------- |
| `auth/`            | register, login, email verification, tokens, sessions, switch-org, me, jwks, invite acceptance |
| `auth/password/`   | forgot / reset / change                                          |
| `auth/mfa/`        | TOTP/SMS/email enrollment + confirmation, the login gate, step-up, recovery codes, factor management |
| `orgs/`            | organization lifecycle, members, invitations, roles              |
| `permissions/`     | the permission catalog                                           |
| `users/`           | user admin (read, update, disable, enable, delete)               |

## Spec schema

```yaml
# <METHOD> <path>: one-line summary.
endpoint:
  method: POST
  path: /auth/login
  summary: Password login
  tags: [auth]
  auth: public            # public | bearer | mfa_token; step-up-gated routes add `step_up: true`
  requires_permissions: [] # the domain's REQUIRES_PERMISSIONS, where declared
  rate_limit: login        # per-IP budget group; omitted when only the global per-user budget applies

input:
  source: body             # body | path | query | none
  fields:                  # field: {type, rules} as the domain validates them
    email: { type: string, rules: [required, email, "max:320"] }

domain:
  class: Univeros\Polaris\Http\Auth\LoginDomain   # the class registered in src/Bootstrap/Routes.php
  description: >
    What the endpoint does, as implemented.

output:
  status: 200
  example: { data: { ... } }   # the implemented envelope

errors:                        # every non-2xx the domain returns
  - { status: 401, code: invalid_credentials }

events: [user.logged_in]       # PSR-14 events emitted (docs/auth/events.md)
```

## Tooling

The `bin/altair spec:scaffold` / `spec:lint` commands (and their skill) ship
with the **host framework**, not with this module; run them from a host
checkout. Scaffolding emits the Action, Input DTO, Responder, Domain stub,
test, route entry, and OpenAPI fragment for a spec. When an endpoint changes,
update its spec, `docs/auth/api-reference.md`, and the functional tests
together; the functional suite is what keeps these specs honest.
