# AGENT.md — univeros/polaris

Agent guide for this package. **Polaris is the official Univeros auth & user
management module**: a pluggable, installable feature a host app wires in with one
line in `config/modules.php`, contributing authentication, MFA/OTP, and
multi-tenant user/organization management. This file is the orientation an agent
should read **before** editing — the human-facing README is `README.md`, and the
full design lives under [`docs/auth/`](docs/auth/).

> **Status:** the implementation has not started — `src/` still contains the
> generated `Sample*` skeleton. The authoritative spec for what to build is in
> [`docs/auth/`](docs/auth/) (design) and [`api/`](api/) (executable endpoint
> specs). Build order is [`docs/auth/implementation-plan.md`](docs/auth/implementation-plan.md).

## The one rule

This package's vendor and namespace are **`univeros/polaris`** and
**`Univeros\Polaris\`** — they are the source of truth (see every `namespace` in
`src/`). Use them everywhere. Do **not** rename to:

- `Altair\*` — the framework's first-party core namespace; or
- one of the framework's read-only split packages (`univeros/http`,
  `univeros/persistence`, `univeros/module`, `univeros/security`,
  `univeros/configuration`, `univeros/cache`, …). Polaris is a distinct module
  that **consumes** those; it is not one of them.

> ⚠️ `composer.json` is still the scaffolder placeholder (`vendor/module` /
> `VendorModule\`), which PSR-4-mismatches the `Univeros\Polaris\` classes in
> `src/` and breaks autoloading. Fixing it is **Phase 0** of the plan — see
> [`docs/auth/configuration.md`](docs/auth/configuration.md#composerjson-fix-required).

## What a module is

`src/Module.php` implements `Altair\Module\Contracts\ModuleInterface` (a
`ConfigurationInterface` + `name()`) and **opts into capabilities by also
implementing the narrow provider contracts** — implement only what you ship:

| Contract | Method | Contributes |
|---|---|---|
| `RoutesProviderInterface` | `routes()` | HTTP routes |
| `MiddlewareProviderInterface` | `middleware()` | PSR-15 middleware, ordered by priority |
| `EntityDirectoriesProviderInterface` | `entityDirectories()` | Cycle entity dirs |
| `MigrationDirectoriesProviderInterface` | `migrationDirectories()` | DB migrations |

Polaris will implement **all four** (it ships routes, auth/authorization
middleware, entities, and migrations). Drop a capability by removing its
interface from the `implements` list. A service-only module needs just
`ModuleInterface` and `univeros/module`.

## The HTTP lifecycle

Endpoints follow **Action -> Input(DTO) -> Domain -> Responder**. The generated
`Univeros\Polaris\Http\Actions\SampleAction` + `SampleInput` + `SampleResponder` +
`Univeros\Polaris\Domain\SampleService` are the canonical pattern — copy their
shape for new endpoints. The Action stays thin: validate via the Input, call the
Domain, hand the result to the Responder.

> The `Sample*` files are placeholders. They are replaced by the auth surface
> defined in [`docs/auth/api-reference.md`](docs/auth/api-reference.md); new
> endpoints are added by scaffolding from a YAML spec in [`api/`](api/) (see the
> caveat below), not by hand where `bin/altair` is available.

## Conventions (non-negotiable)

- `declare(strict_types=1);` in **every** PHP file.
- **Immutability** — never mutate value objects; return new copies via `withX()`.
- **Native types** over PHPDoc; add PHPDoc only for `array<K,V>` shapes / unions PHP
  can't express.
- **Many small files** (200-400 LOC typical), organized by feature.
- **Tests first**, 80%+ coverage on new code. No new code without a test.
- **Security-critical code:** secrets are hashed/encrypted at rest, comparisons
  are constant-time, inputs validated at the boundary, and no user enumeration.
  See [`docs/auth/security.md`](docs/auth/security.md) before touching auth logic.

## Develop and test in isolation (no host app needed)

```bash
composer install
vendor/bin/phpunit
```

`tests/ModuleTest.php` constructs the module and asserts its routes, bindings, and
directories. Grow it as you add behaviour — the host is never involved to test a
module in isolation. The full test strategy + acceptance criteria are in
[`docs/auth/testing.md`](docs/auth/testing.md).

## Scaffolding endpoints — important caveat

The `bin/altair spec:scaffold` YAML flow (write a spec, emit the Action/Input/
Responder/Domain/test) lives in the **framework**, not in this package's
dependencies. So inside this module:

- The spec YAML **vocabulary is not vendored here** — do not guess it. Confirm with
  `bin/altair spec:show <spec>` against a framework install before relying on it.
  The seed specs in [`api/`](api/) are modeled on the documented blocks and carry
  the same caveat (see [`api/README.md`](api/README.md)).
- If `bin/altair` is unavailable, **hand-write** the Action/Input/Responder triple
  following `SampleAction` rather than inventing a structure.

## How a host installs this module

```php
// host app: config/modules.php
return [
    new Univeros\Polaris\Module(),
];
```

Routes, middleware, and migrations are then picked up automatically. Entities
join the host's ORM schema once the host has its one-time
`SchemaProviderInterface` -> `ModuleAwareSchemaProvider` binding wired (a
host-level setup that serves every module, not per-module wiring). Polaris also
requires the host to provide `APP_KEY` + a JWT keypair via env — see
[`docs/auth/configuration.md`](docs/auth/configuration.md).

## Publish

An ordinary Composer package — tag a release and submit to Packagist. Keep the
`univeros/polaris` / `Univeros\Polaris\` vendor/namespace (see "The one rule").

## Canonical docs

- **Auth module spec (this repo):** [`docs/auth/`](docs/auth/) — start at
  [`docs/auth/README.md`](docs/auth/README.md).
- **Executable endpoint specs:** [`api/`](api/).
- Building a module: <https://github.com/univeros/framework/blob/master/docs/guides/extending.md>
- Module contract reference: <https://github.com/univeros/framework/blob/master/docs/packages/module.md>
