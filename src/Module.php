<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Container\Container;
use Altair\Http\Contracts\CredentialsExtractorInterface;
use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Contracts\TokenValidatorInterface;
use Altair\Http\Jwt\SystemClock;
use Altair\Http\Middleware\RateLimit\IpKeyResolver;
use Altair\Http\Middleware\RateLimit\RateLimit;
use Altair\Http\Middleware\RateLimit\RateLimitMiddleware;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Rule\RequestPathRule;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Http\Support\TokenConfiguration;
use Altair\Http\Validator\RepositoryIdentityValidator;
use Altair\Module\Contracts\EntityDirectoriesProviderInterface;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\Contracts\RoutesProviderInterface;
use Altair\Module\Migration\MigrationSource;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Override;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\RateLimitConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Config\TotpConfig;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Event\NullEventDispatcher;
use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Http\Auth\ChangePasswordDomain;
use Univeros\Polaris\Http\Auth\ForgotPasswordDomain;
use Univeros\Polaris\Http\Auth\LoginDomain;
use Univeros\Polaris\Http\Auth\LogoutAllDomain;
use Univeros\Polaris\Http\Auth\LogoutDomain;
use Univeros\Polaris\Http\Auth\MeDomain;
use Univeros\Polaris\Http\Auth\RefreshTokenDomain;
use Univeros\Polaris\Http\Auth\RegisterDomain;
use Univeros\Polaris\Http\Auth\ResendVerificationDomain;
use Univeros\Polaris\Http\Auth\ResetPasswordDomain;
use Univeros\Polaris\Http\Auth\RevokeSessionDomain;
use Univeros\Polaris\Http\Auth\SessionsDomain;
use Univeros\Polaris\Http\Auth\VerifyEmailDomain;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Univeros\Polaris\Http\Middleware\AuthRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\BearerTokenExtractor;
use Univeros\Polaris\Http\Middleware\NullCredentialsExtractor;
use Univeros\Polaris\Http\Middleware\RateLimitGroup;
use Univeros\Polaris\Http\Middleware\UnauthorizedResponder;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Identity\EmailVerificationService;
use Univeros\Polaris\Identity\LoginService;
use Univeros\Polaris\Identity\PasswordPolicy;
use Univeros\Polaris\Identity\PasswordResetService;
use Univeros\Polaris\Identity\RegistrationService;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Mfa\EndroidQrRenderer;
use Univeros\Polaris\Mfa\LogOtpMailer;
use Univeros\Polaris\Mfa\LogSmsSender;
use Univeros\Polaris\Mfa\OtphpTotpProvider;
use Univeros\Polaris\Persistence\EmailVerificationRepository;
use Univeros\Polaris\Persistence\PasswordResetRepository;
use Univeros\Polaris\Persistence\RefreshTokenRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Argon2idPasswordHasher;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Token\DefaultSessionPrincipalResolver;
use Univeros\Polaris\Token\JwtSignerFactory;
use Univeros\Polaris\Token\PolarisTokenFactory;
use Univeros\Polaris\Token\PolarisTokenGenerator;
use Univeros\Polaris\Token\PolarisTokenParser;
use Univeros\Polaris\Token\PolarisTokenValidator;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

use function array_map;
use function getenv;
use function preg_quote;

/**
 * Polaris — the authentication, MFA/OTP, and user/organization management module.
 *
 * A host registers this one class in `config/modules.php` and gets the module's
 * services, routes, Cycle entities, and migrations wired automatically. See
 * `docs/auth/` for the full specification and `docs/auth/implementation-plan.md`
 * for the build order.
 *
 * Phase 0 establishes the foundation: validated configuration ({@see AuthConfig})
 * and required secrets ({@see Secrets}) are built and bound at boot, failing fast
 * when the host has not provided them. Routes, entities, and migrations are
 * contributed by later phases.
 */
final class Module implements
    ModuleInterface,
    RoutesProviderInterface,
    MiddlewareProviderInterface,
    EntityDirectoriesProviderInterface,
    MigrationDirectoriesProviderInterface
{
    /**
     * The `/auth` paths that skip token authentication: the unauthenticated entry points
     * (login, register, email verification, refresh, password forgot/reset) and the public
     * JWKS document. Every other path under `/auth` requires a valid bearer token. Matched as
     * path prefixes by {@see RequestPathRule}, so `/auth/email/verify` also covers
     * `/auth/email/verify/resend`.
     */
    private const array PUBLIC_PATHS = [
        '/auth/login',
        '/auth/register',
        '/auth/email/verify',
        '/auth/token/refresh',
        '/auth/password/forgot',
        '/auth/password/reset',
        '/auth/.well-known/jwks.json',
    ];

    #[Override]
    public function name(): string
    {
        return 'univeros/polaris';
    }

    /**
     * Build and bind the validated configuration and secrets. Both are constructed
     * eagerly so an invalid configuration or a missing secret fails at boot. The
     * identity provider and credential validator are bound lazily — they resolve a
     * repository the persistence module wires.
     */
    #[Override]
    public function apply(Container $container): void
    {
        $authConfig = AuthConfig::fromArray($this->authConfigArray());
        $secrets = Secrets::fromEnvironment($this->environment());

        $container->instance(AuthConfig::class, $authConfig);
        $container->instance(Secrets::class, $secrets);

        $this->bindIdentity($container);
        $this->bindTokens($container, $authConfig, $secrets);
        $this->bindSessions($container);
        $this->bindRegistration($container);
        $this->bindLogin($container);
        $this->bindSessionEndpoints($container);
        $this->bindPasswordReset($container);
        $this->bindMiddleware($container);
        $this->bindMfaProviders($container);
    }

    /**
     * Bind the MFA/OTP delivery ports and their default drivers/providers.
     *
     * Every port is bound only when the host has not already provided one (the same pattern as
     * {@see CacheInterface}/{@see EventDispatcherInterface}), so a host that wires production
     * adapters before registering the module keeps them. SMS and email otherwise default to the
     * dev {@see LogSmsSender}/{@see LogOtpMailer}, which **write the OTP code to the PSR-3 logger**
     * so flows are completable without a provider — a production host MUST bind real
     * {@see SmsSenderInterface}/{@see OtpMailerInterface} adapters (or the {@see NullSmsSender}/
     * {@see NullOtpMailer} no-ops) so codes are never logged. TOTP uses {@see OtphpTotpProvider}
     * (configured from the {@see TotpConfig} inside {@see AuthConfig}); QR rendering uses
     * {@see EndroidQrRenderer} (SVG). A {@see NullLogger} backs the log drivers only when the host
     * has not bound a logger.
     */
    private function bindMfaProviders(Container $container): void
    {
        if (!$container->has(LoggerInterface::class)) {
            $container->singleton(LoggerInterface::class, NullLogger::class);
        }

        $container->singleton(
            TotpConfig::class,
            static fn(AuthConfig $config): TotpConfig => $config->otp->totp,
        );

        $this->bindIfAbsent($container, SmsSenderInterface::class, LogSmsSender::class);
        $this->bindIfAbsent($container, OtpMailerInterface::class, LogOtpMailer::class);
        $this->bindIfAbsent($container, TotpProviderInterface::class, OtphpTotpProvider::class);
        $this->bindIfAbsent($container, QrCodeRendererInterface::class, EndroidQrRenderer::class);
    }

    /**
     * Register a default implementation for a port only when the host has not already bound one.
     *
     * @param class-string $id
     * @param class-string $concrete
     */
    private function bindIfAbsent(Container $container, string $id, string $concrete): void
    {
        if (!$container->has($id)) {
            $container->singleton($id, $concrete);
        }
    }

    /**
     * The PSR-15 middleware Polaris contributes to the host pipeline, ordered against the
     * framework's {@see MiddlewarePriority} anchors:
     *
     * - {@see AuthRateLimitMiddleware} just inside the exception handler (outermost guard), so
     *   abusive traffic is shed before routing or any work.
     * - {@see TokenAuthenticationMiddleware} just after the dispatcher, so it can authenticate
     *   the matched route and attach the access token the protected domains read.
     *
     * (The `AuthorizationMiddleware` — permission/step-up checks — arrives with the RBAC phase.)
     *
     * @return list<array{middleware: class-string, priority: int}>
     */
    #[Override]
    public function middleware(): array
    {
        return [
            ['middleware' => AuthRateLimitMiddleware::class, 'priority' => MiddlewarePriority::EXCEPTION_HANDLER + 50],
            ['middleware' => TokenAuthenticationMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 5],
        ];
    }

    /**
     * Bind the auth-pipeline middleware and its collaborators.
     *
     * {@see TokenAuthenticationMiddleware} is configured with a {@see RequestPathRule} so it only
     * challenges protected `/auth` paths and skips {@see self::PUBLIC_PATHS}; with `ssl => false`
     * because Polaris runs behind the host's TLS termination (the PHP-visible scheme is `http`,
     * and the framework's allow-list guard would otherwise reject every proxied request —
     * transport security is enforced at the edge); and with an {@see UnauthorizedResponder} that
     * renders auth failures as a `401` JSON envelope. A {@see BearerTokenExtractor} reads the
     * `Authorization: Bearer` header, and a {@see NullCredentialsExtractor} disables the
     * credential-minting path so only pre-issued tokens authenticate (login stays the sole
     * credential entry point, with its lockout/MFA/verified-email gates).
     *
     * {@see AuthRateLimitMiddleware} carries one fixed-window limiter per sensitive endpoint
     * group (budgets from {@see RateLimitConfig}). A {@see CacheInterface} is bound to the
     * in-process {@see InMemoryCache} only when the host has not provided one — a production host
     * must bind a shared cache (Redis/APCu/…) for limits to hold across workers.
     */
    private function bindMiddleware(Container $container): void
    {
        $container->singleton(
            TokenExtractorInterface::class,
            static fn(): BearerTokenExtractor => new BearerTokenExtractor(),
        );
        $container->singleton(CredentialsExtractorInterface::class, NullCredentialsExtractor::class);

        if (!$container->has(CacheInterface::class)) {
            $container->singleton(CacheInterface::class, InMemoryCache::class);
        }
        $container->instance(RateLimitConfig::class, RateLimitConfig::defaults());

        $container->singleton(
            TokenAuthenticationMiddleware::class,
            static fn(
                TokenExtractorInterface $tokenExtractor,
                CredentialsExtractorInterface $credentialsExtractor,
                TokenFactoryInterface $tokenFactory,
                IdentityValidatorInterface $identityValidator,
                ResponseFactoryInterface $responseFactory,
            ): TokenAuthenticationMiddleware => new TokenAuthenticationMiddleware(
                $tokenExtractor,
                $credentialsExtractor,
                $tokenFactory,
                $identityValidator,
                $responseFactory,
                [new RequestPathRule([
                    'path' => [preg_quote('/auth', '@')],
                    'passthrough' => self::publicPathPatterns(),
                ])],
                ['ssl' => false, 'onError' => new UnauthorizedResponder()],
            ),
        );

        $container->singleton(
            AuthRateLimitMiddleware::class,
            static fn(
                RateLimitConfig $limits,
                CacheInterface $cache,
                ResponseFactoryInterface $responseFactory,
            ): AuthRateLimitMiddleware => new AuthRateLimitMiddleware(
                self::rateLimitGroup('/auth/login', $limits->login, $cache, $responseFactory),
                self::rateLimitGroup('/auth/register', $limits->register, $cache, $responseFactory),
                self::rateLimitGroup('/auth/password/forgot', $limits->passwordForgot, $cache, $responseFactory),
                self::rateLimitGroup('/auth/token/refresh', $limits->tokenRefresh, $cache, $responseFactory),
            ),
        );
    }

    /**
     * Build one rate-limit group: a {@see RequestPathRule} over the group's path and the
     * framework's fixed-window {@see RateLimitMiddleware} keyed on the client IP.
     */
    private static function rateLimitGroup(
        string $path,
        RateLimit $policy,
        CacheInterface $cache,
        ResponseFactoryInterface $responseFactory,
    ): RateLimitGroup {
        return new RateLimitGroup(
            new RequestPathRule(['path' => [preg_quote($path, '@')]]),
            new RateLimitMiddleware($cache, $policy, $responseFactory, new IpKeyResolver()),
        );
    }

    /**
     * The {@see self::PUBLIC_PATHS} as literal patterns for {@see RequestPathRule}, which
     * interpolates them straight into a regex without escaping. Quoting keeps a metacharacter
     * (e.g. the dots in `.well-known/jwks.json`) from matching more than the intended literal
     * path — which could otherwise let a future route slip past authentication.
     *
     * @return list<string>
     */
    private static function publicPathPatterns(): array
    {
        return array_map(static fn(string $path): string => preg_quote($path, '@'), self::PUBLIC_PATHS);
    }

    /**
     * Bind the password reset/change and `/auth/me` machinery: {@see PasswordResetService}
     * (forgot/reset/change with logout-everywhere on a credential change) and the domains
     * behind `/auth/password/{forgot,reset,change}` and `GET /auth/me`.
     */
    private function bindPasswordReset(Container $container): void
    {
        $container->singleton(
            PasswordResetService::class,
            static fn(
                UserRepository $users,
                PasswordResetRepository $resets,
                UnitOfWorkInterface $unitOfWork,
                PasswordHasherInterface $hasher,
                PasswordPolicy $policy,
                Pepper $pepper,
                SessionService $sessions,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): PasswordResetService => new PasswordResetService(
                $users,
                $resets,
                $unitOfWork,
                $hasher,
                $policy,
                $pepper,
                $sessions,
                $clock,
                $events,
            ),
        );

        $container->singleton(ForgotPasswordDomain::class);
        $container->singleton(ResetPasswordDomain::class);
        $container->singleton(ChangePasswordDomain::class);
        $container->singleton(
            MeDomain::class,
            static fn(UserRepository $users): MeDomain => new MeDomain($users),
        );
    }

    /**
     * Bind the refresh + session-management endpoints: {@see SessionService} and the
     * domains behind `/auth/token/refresh`, `/auth/logout`, `/auth/logout-all`, and
     * `/auth/sessions`. The mutating session endpoints read the access token the auth
     * middleware (issue #15) attaches to the request.
     */
    private function bindSessionEndpoints(Container $container): void
    {
        $container->singleton(
            SessionService::class,
            static fn(
                RefreshTokenRepository $refreshTokens,
                TokenService $tokens,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): SessionService => new SessionService($refreshTokens, $tokens, $clock, $events),
        );

        $container->singleton(RefreshTokenDomain::class);
        $container->singleton(LogoutDomain::class);
        $container->singleton(LogoutAllDomain::class);
        $container->singleton(SessionsDomain::class);
        $container->singleton(RevokeSessionDomain::class);
    }

    /**
     * Bind the password-login machinery: {@see LoginService} (constant-time verification,
     * status/lockout/verified checks, token issuance via {@see TokenService}) and the
     * {@see LoginDomain} behind `POST /auth/login`.
     */
    private function bindLogin(Container $container): void
    {
        $container->singleton(
            LoginService::class,
            static fn(
                UserRepository $users,
                PasswordHasherInterface $hasher,
                TokenService $tokens,
                UnitOfWorkInterface $unitOfWork,
                AuthConfig $config,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): LoginService => new LoginService(
                $users,
                $hasher,
                $tokens,
                $unitOfWork,
                $config,
                $clock,
                $events,
            ),
        );

        $container->singleton(LoginDomain::class);
    }

    /**
     * Bind the registration + email-verification machinery: the Argon2id hasher and
     * password policy, and the {@see RegistrationService}/{@see EmailVerificationService}
     * domains behind the `/auth/register` and `/auth/email/verify` endpoints.
     */
    private function bindRegistration(Container $container): void
    {
        $container->singleton(PasswordHasherInterface::class, Argon2idPasswordHasher::class);
        $container->singleton(
            PasswordPolicy::class,
            static fn(AuthConfig $config): PasswordPolicy => new PasswordPolicy($config->passwordMinLength),
        );

        $container->singleton(
            EmailVerificationService::class,
            static fn(
                UserRepository $users,
                EmailVerificationRepository $verifications,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): EmailVerificationService => new EmailVerificationService(
                $users,
                $verifications,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );

        $container->singleton(
            RegistrationService::class,
            static fn(
                UserRepository $users,
                EmailVerificationService $verifications,
                UnitOfWorkInterface $unitOfWork,
                PasswordHasherInterface $hasher,
                PasswordPolicy $policy,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): RegistrationService => new RegistrationService(
                $users,
                $verifications,
                $unitOfWork,
                $hasher,
                $policy,
                $clock,
                $events,
            ),
        );

        $container->singleton(RegisterDomain::class);
        $container->singleton(VerifyEmailDomain::class);
        $container->singleton(ResendVerificationDomain::class);
    }

    /**
     * Bind the session machinery: the keyed {@see Pepper} (refresh-token hashing), a
     * no-op PSR-14 dispatcher (until the host wires listeners in Phase 4), the default
     * {@see SessionPrincipalResolverInterface} (RBAC rebinds it later), and
     * {@see TokenService}, which issues and rotates refresh tokens with reuse detection.
     */
    private function bindSessions(Container $container): void
    {
        $container->singleton(Pepper::class, static fn(Secrets $secrets): Pepper => new Pepper($secrets->appKey));

        // Only fall back to the no-op dispatcher when the host has not wired a real one,
        // so a host-provided PSR-14 dispatcher (and its security listeners) is preserved.
        if (!$container->has(EventDispatcherInterface::class)) {
            $container->singleton(EventDispatcherInterface::class, NullEventDispatcher::class);
        }
        $container->singleton(
            SessionPrincipalResolverInterface::class,
            static fn(UserRepository $users): DefaultSessionPrincipalResolver
                => new DefaultSessionPrincipalResolver($users),
        );

        $container->singleton(
            TokenService::class,
            static fn(
                RefreshTokenRepository $refreshTokens,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                TokenGeneratorInterface $accessTokens,
                SessionPrincipalResolverInterface $principals,
                AuthConfig $config,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): TokenService => new TokenService(
                $refreshTokens,
                $unitOfWork,
                $pepper,
                $accessTokens,
                $principals,
                $config,
                $clock,
                $events,
            ),
        );
    }

    /**
     * Bind the JWT machinery: a {@see TokenConfigurationInterface} derived from
     * {@see AuthConfig} (issuer/audience/ttl/signer) and {@see Secrets} (keys), the
     * Polaris generator (full claim set + `kid` header), and the parser/validator/factory
     * that verify tokens against the public key. Issuance time (`iat`/`exp`/`nbf`) is
     * derived from the injected {@see ClockInterface} at mint time, not from the
     * configuration, so the configuration carries only static values.
     */
    private function bindTokens(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $container->singleton(ClockInterface::class, SystemClock::class);

        $container->singleton(
            TokenConfigurationInterface::class,
            static function () use ($authConfig, $secrets): TokenConfiguration {
                $publicKey = $secrets->jwtPublicKey;
                $issuer = $authConfig->issuer;
                if ($publicKey === '' || $issuer === '') {
                    throw new InvalidConfigException('A JWT public key and issuer are required to mint tokens.');
                }

                return new TokenConfiguration(
                    $publicKey,
                    $authConfig->accessToken->ttl,
                    JwtSignerFactory::create($authConfig->accessToken->signer),
                    $issuer,
                    null,
                    $secrets->jwtPrivateKey,
                    $authConfig->audience,
                );
            },
        );

        $keyId = $secrets->jwtKid;
        $container->singleton(
            TokenGeneratorInterface::class,
            static fn(TokenConfigurationInterface $config, ClockInterface $clock): PolarisTokenGenerator
                => new PolarisTokenGenerator($config, $clock, $keyId),
        );

        $container->singleton(TokenParserInterface::class, PolarisTokenParser::class);
        $container->singleton(TokenValidatorInterface::class, PolarisTokenValidator::class);
        $container->singleton(TokenFactoryInterface::class, PolarisTokenFactory::class);
        $container->singleton(JwksDomain::class);
    }

    /**
     * Bind the framework's Http auth contracts: a {@see CycleIdentityProvider} over
     * the {@see UserRepository}, and the framework's {@see RepositoryIdentityValidator}
     * mapping its `username`/`hash` options onto the User's email and password-hash
     * columns. Credentials authenticate when valid and are rejected otherwise.
     *
     * This is a password-only credential check. Account `status`/lockout, MFA, and
     * the timing equalization that prevents user enumeration are enforced by the
     * login flow (Phase 1), not here — a `true` result is not by itself a grant.
     */
    private function bindIdentity(Container $container): void
    {
        $container->singleton(
            IdentityProviderInterface::class,
            static fn(UserRepository $users): CycleIdentityProvider => new CycleIdentityProvider($users),
        );

        $container->singleton(
            IdentityValidatorInterface::class,
            static fn(IdentityProviderInterface $provider): RepositoryIdentityValidator
                => new RepositoryIdentityValidator($provider, [
                    'username' => CycleIdentityProvider::IDENTIFIER_FIELD,
                    'hash' => CycleIdentityProvider::PASSWORD_HASH_FIELD,
                ]),
        );
    }

    /**
     * @return list<array{0: string, 1: string, 2: class-string}>
     */
    #[Override]
    public function routes(): array
    {
        // See docs/auth/api-reference.md; more endpoints land in later Phase 1 issues.
        return [
            ['GET', '/auth/.well-known/jwks.json', JwksDomain::class],
            ['POST', '/auth/register', RegisterDomain::class],
            ['POST', '/auth/email/verify', VerifyEmailDomain::class],
            ['POST', '/auth/email/verify/resend', ResendVerificationDomain::class],
            ['POST', '/auth/login', LoginDomain::class],
            ['POST', '/auth/token/refresh', RefreshTokenDomain::class],
            ['POST', '/auth/logout', LogoutDomain::class],
            ['POST', '/auth/logout-all', LogoutAllDomain::class],
            ['GET', '/auth/sessions', SessionsDomain::class],
            ['DELETE', '/auth/sessions/{id}', RevokeSessionDomain::class],
            ['POST', '/auth/password/forgot', ForgotPasswordDomain::class],
            ['POST', '/auth/password/reset', ResetPasswordDomain::class],
            ['POST', '/auth/password/change', ChangePasswordDomain::class],
            ['GET', '/auth/me', MeDomain::class],
        ];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function entityDirectories(): array
    {
        return [__DIR__ . '/Entity'];
    }

    /**
     * @return list<MigrationSource>
     */
    #[Override]
    public function migrationDirectories(): array
    {
        return [
            new MigrationSource(
                \dirname(__DIR__) . '/database/migrations',
                __NAMESPACE__ . '\\Database\\Migrations',
            ),
        ];
    }

    /**
     * The host's `auth` config namespace. Until the host-config bridge lands
     * (Phase 1), only the issuer/audience are sourced from the environment and the
     * rest of {@see AuthConfig} uses its documented defaults.
     *
     * @return array<string, mixed>
     */
    private function authConfigArray(): array
    {
        $issuer = getenv('AUTH_ISSUER');
        $audience = getenv('AUTH_AUDIENCE');

        return [
            'issuer' => $issuer !== false && $issuer !== '' ? $issuer : 'univeros/polaris',
            'audience' => $audience !== false && $audience !== '' ? $audience : null,
        ];
    }

    /**
     * The subset of the environment Polaris reads its secrets from.
     *
     * @return array<string, string>
     */
    private function environment(): array
    {
        $env = [];
        foreach (['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_JWT_KID'] as $key) {
            $value = getenv($key);
            if ($value !== false) {
                $env[$key] = $value;
            }
        }

        return $env;
    }
}
