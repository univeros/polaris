# Configuration, Bindings & Dependencies

How a host configures Polaris, what the module binds in the container, and the
libraries the module pulls in.

---

## 1. Module config schema

Polaris reads a single `auth` config namespace (via `univeros/configuration`).
Every value has a safe default; a host overrides only what it needs. Shown with
defaults:

```php
return [
    'auth' => [
        'tenancy'    => 'multi',          // fixed for this build
        'identifier' => 'email',          // primary login identifier

        'issuer'   => 'https://auth.example.com',
        'audience' => 'https://api.example.com',

        'access_token' => [
            'ttl'          => 900,        // seconds (15 min)
            'signer'       => 'RS256',    // RS256 | EdDSA
            'embed_scope'  => false,      // embed flat permissions vs roles only
            'denylist'     => false,      // optional jti denylist for instant revoke
        ],

        'refresh_token' => [
            'ttl'             => 2592000, // 30 days
            'rotation'        => true,    // rotate on every use (recommended)
            'reuse_detection' => true,    // revoke family on replay
            'sliding'         => false,   // extend expiry on use
            'max_lifetime'    => 7776000, // 90d cap when sliding
        ],

        'password' => [
            'algo'        => 'argon2id',
            'min_length'  => 12,
            'breach_check'=> false,       // enable HIBP-style check (needs adapter)
        ],

        'lockout' => [
            'max_attempts'       => 5,
            'window'             => 900,  // 15 min
            'lock_duration'      => 900,
            'trust_known_devices'=> true,
        ],

        'otp' => [
            'length'          => 6,
            'ttl'             => 300,     // 5 min (sms/email)
            'max_attempts'    => 5,
            'resend_cooldown' => 30,
            'totp' => [
                'digits'    => 6,
                'period'    => 30,
                'algorithm' => 'SHA1',    // authenticator-app standard
                'window'    => 1,         // ±1 step skew tolerance
                'issuer'    => 'Univeros',// label shown in the authenticator app
            ],
        ],

        'mfa' => [
            'enforce'      => false,      // require MFA for all users
            'grace_enroll' => true,       // allow login-then-enroll when enforced
        ],

        'step_up' => [ 'max_age' => 300 ],

        'flows' => [
            'require_verified_email' => true,
            'token_delivery'         => 'body',  // body | cookie
            'email_verification'     => [ 'style' => 'link', 'ttl' => 86400 ],
            'password_reset'         => [ 'style' => 'link', 'ttl' => 3600 ],
            'invitation'             => [ 'ttl' => 604800 ], // 7 days
        ],

        'rate_limits' => [ /* per-group overrides — see security.md §5 */ ],
    ],
];
```

A typed `AuthConfig` value object wraps this (validated at boot); domain services
depend on `AuthConfig`, never on raw arrays — fail-fast on invalid/missing
required values (issuer, keys).

---

## 2. Environment variables

Secrets come from env / a secret manager, never config files:

| Variable                | Required | Purpose                                            |
| ----------------------- | -------- | -------------------------------------------------- |
| `APP_KEY`               | yes      | seeds HKDF peppers + `Encrypter` key               |
| `AUTH_JWT_PRIVATE_KEY`  | yes      | PEM private key (sign access tokens)               |
| `AUTH_JWT_PUBLIC_KEY`   | yes      | PEM public key (verify / JWKS)                     |
| `AUTH_JWT_KID`          | rec.     | key id for rotation (defaults to a hash of pubkey) |
| `AUTH_ISSUER`           | rec.     | overrides `auth.issuer`                            |
| `AUTH_AUDIENCE`         | rec.     | overrides `auth.audience`                          |

`Module::apply()` asserts the required env is present and well-formed and throws
a clear startup error otherwise (no silent insecure fallback).

---

## 3. Container bindings (`Module::apply()`)

Polaris binds its ports to concrete implementations and provides the framework
auth contracts. Hosts override any binding *after* registering the module.

```php
public function apply(Container $container): void
{
    // ---- config ----
    $container->singleton(AuthConfig::class, /* factory from 'auth' config + env */);

    // ---- framework Http auth contract implementations ----
    $container->singleton(IdentityProviderInterface::class, CycleIdentityProvider::class);
    $container->singleton(IdentityValidatorInterface::class, fn($c) =>
        new RepositoryIdentityValidator(
            $c->get(IdentityProviderInterface::class),
            ['username' => 'email', 'hash' => 'password_hash'],
        ));
    $container->singleton(TokenConfigurationInterface::class, /* from AuthConfig + keys */);
    $container->singleton(TokenGeneratorInterface::class, LcobucciTokenGenerator::class);
    $container->singleton(TokenParserInterface::class, /* Polaris parser over LcobucciTokenParser */);
    $container->singleton(TokenFactoryInterface::class, PolarisTokenFactory::class);
    $container->singleton(TokenValidatorInterface::class, PolarisTokenValidator::class);
    $container->singleton(TokenExtractorInterface::class, HeaderTokenExtractor::class);
    $container->singleton(CredentialsExtractorInterface::class, BodyCredentialsExtractor::class);

    // ---- Polaris ports (host rebinds for production) ----
    $container->singleton(PasswordHasherInterface::class, Argon2idPasswordHasher::class);
    $container->singleton(SmsSenderInterface::class, LogSmsSender::class);   // dev default
    $container->singleton(OtpMailerInterface::class, LogOtpMailer::class);   // dev default
    $container->singleton(BreachedPasswordCheckInterface::class, NullBreachCheck::class);
    $container->singleton(TotpProviderInterface::class, OtphpTotpProvider::class);
    $container->singleton(QrCodeRendererInterface::class, EndroidQrRenderer::class);
    $container->singleton(ClockInterface::class, SystemClock::class);        // lcobucci/clock

    // ---- domain services (autowired; bound as singletons for sharing) ----
    $container->singleton(RegistrationService::class);
    $container->singleton(LoginService::class);
    $container->singleton(TokenService::class);          // mint/rotate/refresh
    $container->singleton(MfaService::class);
    $container->singleton(OtpService::class);
    $container->singleton(OrganizationService::class);
    $container->singleton(MembershipService::class);
    $container->singleton(RoleService::class);
    $container->singleton(PermissionResolver::class);
    $container->singleton(Gate::class);
}
```

### Middleware contribution (`MiddlewareProviderInterface`)

```php
public function middleware(): array
{
    return [
        // authenticate bearer/credentials → attaches TokenInterface to request
        ['middleware' => TokenAuthenticationMiddleware::class,
         'priority'   => MiddlewarePriority::DISPATCHER + 5],
        // authorize: permission + step-up checks declared on the Action
        ['middleware' => AuthorizationMiddleware::class,
         'priority'   => MiddlewarePriority::DISPATCHER + 10],
        // rate limiting for auth endpoints (own priority, outer)
        ['middleware' => AuthRateLimitMiddleware::class,
         'priority'   => MiddlewarePriority::EXCEPTION_HANDLER + 50],
    ];
}
```

`TokenAuthenticationMiddleware` is configured with **rules** (`HttpAuthRule`) so
it only challenges protected paths and skips the public ones (`/auth/login`,
`/auth/register`, JWKS, …).

---

## 4. Dependencies to add

Added to `composer.json` `require` (all actively maintained, permissive
licenses; versions to be pinned at implementation time):

| Package                  | Why                                              | Notes                          |
| ------------------------ | ------------------------------------------------ | ------------------------------ |
| `spomky-labs/otphp`      | RFC 6238/4226 TOTP/HOTP generate + verify        | pure PHP                        |
| `endroid/qr-code`        | Render `otpauth://` URI as QR (SVG default, PNG) | wraps `bacon/bacon-qr-code`     |
| `symfony/uid`            | UUID v7 primary keys                             | symfony already partly vendored |

Already available (no new dep):

- `lcobucci/jwt` + `lcobucci/clock` — JWT signing/verification (via `univeros/http`).
- `Altair\Security\Encrypter`, `HkdfKey`, `Salt` — encryption + key derivation.
- Cycle ORM + migrations (via `univeros/persistence`).
- `password_hash`/`password_verify` (PHP core, Argon2id with sodium).

> **No SMS/email SDK is added to core.** Delivery is via the `SmsSenderInterface`
> / `OtpMailerInterface` ports; concrete Twilio/SES/SMTP adapters live in the
> optional `univeros/polaris-adapters` package (see
> [implementation-plan.md](implementation-plan.md#optional-adapters)).

### composer.json fix required

The skeleton `composer.json` still has the placeholder name/namespace and must be
corrected to match the source (`Univeros\Polaris`):

```diff
- "name": "vendor/module",
+ "name": "univeros/polaris",
- "description": "A Univeros module.",
+ "description": "Authentication, MFA/OTP, and user/organization management for Univeros apps.",
  "autoload": {
-     "psr-4": { "VendorModule\\": "src/" }
+     "psr-4": { "Univeros\\Polaris\\": "src/" }
  },
  "autoload-dev": {
-     "psr-4": { "VendorModule\\Tests\\": "tests/" }
+     "psr-4": { "Univeros\\Polaris\\Tests\\": "tests/" }
  },
  "require": {
      "php": ">=8.3",
      "univeros/module": "^2.0",
      "univeros/http": "^2.0",
      "univeros/persistence": "^2.0",
+     "univeros/security": "^2.0",
+     "spomky-labs/otphp": "^11.3",
+     "endroid/qr-code": "^6.0",
+     "symfony/uid": "^7.0"
  }
```

---

## 5. Host setup (end to end)

```php
// config/modules.php
return [
    new Univeros\Polaris\Module(),
];
```

```bash
# 1. install
composer require univeros/polaris

# 2. provide secrets (env / secret manager)
export APP_KEY=…              # 32-byte base64
export AUTH_JWT_PRIVATE_KEY="$(cat private.pem)"
export AUTH_JWT_PUBLIC_KEY="$(cat public.pem)"

# 3. apply migrations (Polaris's tables join the host's tracking table)
bin/altair db:migrate

# 4. (optional) bind production providers in the host container
#    SmsSenderInterface → TwilioSmsSender, OtpMailerInterface → SymfonyMailerAdapter

# 5. verify wiring
bin/altair routes:list --format=json | grep auth
bin/altair doctor
```

That single module registration contributes all `/auth`, `/users`, `/orgs`
routes, the entities, the migrations, the middleware, and the bindings — **no
per-module host wiring**, per the Univeros module contract.

> The only host-level prerequisite (shared by every module, not specific to
> Polaris) is the one-time `SchemaProviderInterface` → `ModuleAwareSchemaProvider`
> binding that lets module entities join the host's ORM schema. Once a host has
> that, registering Polaris needs nothing further beyond the secrets in §2.
