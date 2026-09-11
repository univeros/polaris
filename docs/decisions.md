# Decisions: univeros/polaris 2.0

Append only, dated. The owner's decisions of 2026-09-10 (the new major on `polaris/core`, `polaris/psr15`,
`polaris/pdo` and `polaris/cli`; `PolarisMiddleware` ahead of the framework's exception handler; no
compatibility encrypter; one Cycle migration over `Polaris\Pdo\SchemaInstaller`; the HTTP contract frozen by
the 184 recorded fixtures) are recorded in `polaris-core`'s `docs/adapters/univeros-polaris-2.0.md`, the
hand-off this work applies. What follows is what was decided while applying it.

## Log

- 2026-09-11 · WP0 · `1.x` is a branch cut at `v1.0.0` (pushed before the first 2.0 change), so a 1.x fix has
  a home; `main` carries 2.0. Work packages are branches named `2.0/wpN` from a fresh `main`, one PR each,
  squash-merged with the subject `<type>: <description> (#N)`.
- 2026-09-11 · WP0 · `docs/auth/` stays as the design reference (the data model, the flows, the MFA and RBAC
  rules, the API reference and the security model are the ones `polaris/core` implements, contract-frozen);
  its README says that the implementation is `polaris/core` and that only the module glue lives here.
  · Rejected: deleting the directory (the design has no other home in this repository and the 2.0 README
  links to it); rewriting it against the `Polaris\` namespaces (the same text lives in `polaris-core`'s
  `docs/auth/`, maintained there).
- 2026-09-11 · WP0 · `BearerTokenExtractor`, `NullCredentialsExtractor` and `UnauthorizedResponder` stay in
  WP0, moved from `src/Http/Middleware/` to `src/Http/` with their tests, rather than deleted and re-added
  in WP1: they did not move into `polaris/core` (the hand-off lists them as kept from 1.0) and they depend
  on nothing that was deleted. `src/` is otherwise the placeholder module only.
- 2026-09-11 · WP0 · `composer qa` runs `cs`, `stan` and `test`; `test:contract` (the functional suite through
  the module's harness) is declared now and joins `qa` and CI in WP3, when `tests/Harness.php` exists.
  `composer test` already runs the `functional` suite through `polaris/core`'s default `PipelineHarness`,
  which proves in WP0 that the vendored suite (the `Polaris\Tests\` autoload-dev mapping, `polaris/testing`,
  `httpsoft/http-message`, the fixtures) runs from this repository. · Rejected: a `qa` that fails until WP3.
- 2026-09-11 · WP0 · `migrations/` exists from WP0 (a `.gitkeep`) so `phpstan.neon` and `phpcs.xml` can list
  `src`, `tests` and `migrations` before the migration lands in WP2.
- 2026-09-11 · WP0 · `.ai/skills/polaris/SKILL.md`, `README.md`, `CHANGELOG.md` and `AGENT.md` still describe
  1.x until WP4, the documentation work package; WP0 changes no prose except this file and the `docs/auth`
  note.
