# univeros/polaris on the Univeros skeleton

The demo host: `composer create-project univeros/univeros` with the Polaris module registered, Cycle on
a SQLite file, emails written to `var/mail.log`. The same walkthrough as the Slim, Laravel, Symfony and
Yii demos of Polaris for PHP, from a clean clone in about a minute.

```sh
cd examples/univeros
composer install
bin/setup            # .env with APP_KEY and an RS256 key pair, db:migrate, polaris:schema:diff, polaris:doctor
composer serve       # php -S 127.0.0.1:8080 -t public, in another terminal
bin/walkthrough.sh   # register, verify, login, TOTP, MFA login, organization, switch-org, then GET /app/me
```

`bin/walkthrough.sh` starts its own server when none is running, so `composer install && bin/setup &&
bin/walkthrough.sh` is enough.

## What the host provides

The skeleton's `public/index.php` and `config/container.php` are unchanged. The application adds:

- [`config/modules.php`](config/modules.php): `App\AppModule` (the demo's own module) and
  `Univeros\Polaris\Module`.
- [`config/configurations.php`](config/configurations.php): `EnvironmentConfiguration` (`.env`),
  `LoggingConfiguration`, `CycleOrmConfiguration` (the `DB_*` settings Polaris shares).
- [`app/AppModule.php`](app/AppModule.php): binds the mailbox ([`app/Mail/FileMailer.php`](app/Mail/FileMailer.php),
  one JSON line per email in `var/mail.log`) as Polaris's mailer, and the framework's
  `TokenAuthenticationMiddleware`, as the Polaris module binds it, scoped to `/app` with a
  `RequestPathRule` at `DISPATCHER + 5` ([`app/Http/Middleware/AppAuthentication.php`](app/Http/Middleware/AppAuthentication.php)).
- [`config/routes.php`](config/routes.php): the skeleton's `GET /ping` and `GET /app/me`
  ([`app/Account/Me.php`](app/Account/Me.php)), which reads the Polaris access token the middleware
  attached and answers with the user from Polaris's repositories. The Polaris routes are not listed:
  the module's middleware serves them before the dispatcher.
- [`bin/altair`](bin/altair): the application's console, building `config/container.php` first and
  adding the `polaris:*` commands, so `db:migrate` finds the ORM and the module's migration.
- [`bin/setup`](bin/setup): `.env` from `.env.example` with a generated `APP_KEY` and the key pair
  (`var/keys/`, also inlined as quoted multi-line values), then `db:migrate`, `polaris:schema:diff` and
  `polaris:doctor`.

Swap `DB_CONNECTION` for `postgres` or `mysql`, the file mailer for your transport, bind a PSR-16 cache
that outlives a request, and the same application runs in production.

Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
