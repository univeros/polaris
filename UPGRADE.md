# Upgrading from 2.2 to 2.3

1. 2.3 requires univeros/* `^2.6`. With an application locked to framework 2.5, update them together:
   `composer require univeros/polaris:^2.3 -W` (or `composer update 'univeros/*' -W`).
   Nothing else changes.

# Upgrading from 2.0 to 2.1

1. If you bind a PSR-14 dispatcher and subscribed `$polaris->listeners()` to it (2.0's advice), either
   remove that subscription (the module now runs the Polaris listeners, then your dispatcher) or set
   `POLARIS_LISTENERS=host` to keep 2.0's behaviour. Doing neither runs the audit log, notifications
   and metrics twice per event.

# Upgrading from 1.x to 2.0

2.0 is a breaking change. 1.x installations are not affected by this release and keep
working (the `1.x` branch carries them); upgrade when you can re-enrol MFA.

1. `composer require univeros/polaris:^2.0`. The `polaris/*` packages come with it.
2. Replace `Univeros\Polaris\*` imports with the `Polaris\*` classes of `polaris/core`
   (`Polaris\Model\User`, `Polaris\Event\*`, `Polaris\Contract\*`); the module itself stays
   `Univeros\Polaris\Module` in `config/modules.php`.
3. Database: 2.0 does not migrate 1.x tables. On a new database `bin/altair db:migrate`
   installs the 2.0 schema. On an existing one, export your users and organizations, install
   2.0, and import them; `bin/altair polaris:schema:diff` reports any difference between the
   database and the schema 2.0 expects. The application ships its own `bin/altair` (see the
   README): the framework's `vendor/bin/altair` boots without the application's container.
4. TOTP secrets encrypted by 1.x cannot be read by 2.0: the encrypter changed (XChaCha20-Poly1305
   keyed by HKDF from `APP_KEY`) and no compatibility decrypter is provided. Users re-enrol their
   TOTP factors after the upgrade. Recovery codes are stored hashed under a key derived from
   `APP_KEY`; prove in a test that 1.x hashes verify under 2.0 before relying on it, otherwise
   users regenerate them after re-enrolling.
5. The Polaris routes are no longer in the FastRoute table: if your application listed or
   overrode them in `config/routes.php`, remove those entries. Your own routes keep using the
   framework's `TokenAuthenticationMiddleware`, scoped to your protected paths with
   `$container->make(TokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule([...])]])`.
6. Subscribe `$polaris->listeners()` to your PSR-14 dispatcher if you bind one; without one the
   module dispatches Polaris events itself.
7. Set `AUTH_ISSUER` if your clients check the `iss` claim: the default without it is now
   `polaris` (1.x minted `univeros/polaris`). No 1.x token outlives the upgrade, so nothing
   else changes.
