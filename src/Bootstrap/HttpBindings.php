<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Altair\Http\Contracts\CredentialsExtractorInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Middleware\RateLimit\IpKeyResolver;
use Altair\Http\Middleware\RateLimit\RateLimit;
use Altair\Http\Middleware\RateLimit\RateLimitMiddleware;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Rule\RequestPathRule;
use Altair\Observability\Contracts\RecorderInterface;
use Altair\Observability\Metrics\Meter;
use Altair\Observability\Recorder\InMemoryRecorder;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Authorization\Gate;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\RateLimitConfig;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Http\Middleware\AuthenticatedRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\AuthorizationMiddleware;
use Univeros\Polaris\Http\Middleware\AuthRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\BearerTokenExtractor;
use Univeros\Polaris\Http\Middleware\ClientContextMiddleware;
use Univeros\Polaris\Http\Middleware\DenylistMiddleware;
use Univeros\Polaris\Http\Middleware\NullCredentialsExtractor;
use Univeros\Polaris\Http\Middleware\RateLimitGroup;
use Univeros\Polaris\Http\Middleware\TokenSubjectKeyResolver;
use Univeros\Polaris\Http\Middleware\UnauthorizedResponder;
use Univeros\Polaris\Maintenance\PruneExpiredService;
use Univeros\Polaris\Notification\NotificationListener;
use Univeros\Polaris\Observability\AuditLogListener;
use Univeros\Polaris\Observability\MetricsListener;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Token\AccessTokenDenylist;

use function array_map;
use function preg_quote;

/**
 * Wires the auth-pipeline middleware: token authentication over the protected paths,
 * the rate limiters, authorization, and the observability/notification listeners.
 */
final class HttpBindings
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
        // The MFA-gate routes carry the single-purpose `login_mfa` ticket, not an access token, so
        // they bypass the access-token middleware; {@see MfaTokenMiddleware} authenticates them.
        '/auth/mfa/challenge',
        '/auth/mfa/verify',
    ];

    public function apply(Container $container): void
    {
        $this->bindMiddleware($container);
    }

    /**
     * Bind the auth-pipeline middleware and its collaborators.
     *
     * {@see TokenAuthenticationMiddleware} is configured with a {@see RequestPathRule} so it only
     * challenges protected `/auth` and `/orgs` paths and skips {@see self::PUBLIC_PATHS}; with `ssl => false`
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
                    'path' => [
                        preg_quote('/auth', '@'),
                        preg_quote('/orgs', '@'),
                        preg_quote('/permissions', '@'),
                        preg_quote('/users', '@'),
                    ],
                    'passthrough' => self::publicPathPatterns(),
                ])],
                ['ssl' => false, 'onError' => new UnauthorizedResponder()],
            ),
        );

        $container->singleton(Gate::class, static fn(PermissionResolver $permissions): Gate => new Gate($permissions));

        // The append-only audit trail (#38) and user-facing notifications (#39). Polaris ships
        // the listeners; the host subscribes them to its PSR-14 dispatcher for the
        // Univeros\Polaris\Event\* classes (docs/auth/events.md).
        $container->singleton(AuditLogListener::class);

        // Transient-row pruning (#40); the host wires it to its scheduler (bin/altair job or cron).
        $container->singleton(PruneExpiredService::class);

        // Optional instant access-token revocation (#41, security.access_token.denylist).
        $container->singleton(
            AccessTokenDenylist::class,
            static fn(CacheInterface $cache, ClockInterface $clock, AuthConfig $config): AccessTokenDenylist
                => new AccessTokenDenylist($cache, $clock, $config->accessToken->ttl),
        );
        $container->singleton(
            DenylistMiddleware::class,
            static fn(
                AccessTokenDenylist $denylist,
                AuthConfig $config,
                ResponseFactoryInterface $responseFactory,
            ): DenylistMiddleware => new DenylistMiddleware($denylist, $config, $responseFactory),
        );

        // Auth domain metrics (#42): one polaris.auth.events counter, event name as attribute.
        // The framework's ObservabilityConfiguration normally binds the recorder/Meter; default
        // them only when the host has not, mirroring the LoggerInterface fallback.
        if (!$container->has(RecorderInterface::class)) {
            $container->singleton(RecorderInterface::class, InMemoryRecorder::class);
        }
        if (!$container->has(Meter::class)) {
            $container->singleton(Meter::class, static fn(RecorderInterface $recorder): Meter => new Meter($recorder));
        }
        $container->singleton(
            MetricsListener::class,
            static fn(Meter $meter, LoggerInterface $logger): MetricsListener => new MetricsListener($meter, $logger),
        );
        $container->singleton(
            NotificationListener::class,
            static fn(
                OtpMailerInterface $mailer,
                UserRepository $users,
                LoggerInterface $logger,
            ): NotificationListener => new NotificationListener($mailer, $users, $logger),
        );
        $container->singleton(
            AuthorizationMiddleware::class,
            static fn(Gate $gate, ResponseFactoryInterface $responseFactory): AuthorizationMiddleware
                => new AuthorizationMiddleware($gate, $responseFactory),
        );

        $container->singleton(ClientContextMiddleware::class);

        // The global authenticated budget: one fixed window per user id across every
        // authenticated endpoint, keyed on the token's `sub` (#97).
        $container->singleton(
            AuthenticatedRateLimitMiddleware::class,
            static fn(
                RateLimitConfig $limits,
                CacheInterface $cache,
                ResponseFactoryInterface $responseFactory,
            ): AuthenticatedRateLimitMiddleware => new AuthenticatedRateLimitMiddleware(
                new RateLimitMiddleware($cache, $limits->authenticated, $responseFactory, new TokenSubjectKeyResolver()),
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
                // Single-use-token consumers: each call hashes attacker-supplied input and hits
                // the database, so they share a per-IP guessing budget. The /auth/email/verify
                // prefix also covers /auth/email/verify/resend (DB writes + an outbound mail).
                self::rateLimitGroup('/auth/email/verify', $limits->tokenConsume, $cache, $responseFactory),
                self::rateLimitGroup('/auth/password/reset', $limits->tokenConsume, $cache, $responseFactory),
                self::rateLimitGroup('/auth/invites/accept', $limits->tokenConsume, $cache, $responseFactory),
                // Throttle the brute-forceable 6-digit MFA confirms/verify and cap factor/send churn.
                // The more specific step-up/challenge path is listed before /step-up so it wins the
                // first-match: a sent code is throttled as a send, the verify as a confirm.
                self::rateLimitGroup('/auth/mfa/verify', $limits->mfaConfirm, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/challenge', $limits->mfaSend, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/step-up/challenge', $limits->mfaSend, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/step-up', $limits->mfaConfirm, $cache, $responseFactory),
                // Factor management (list/patch/delete) gets a moderate per-IP budget like enrollment.
                self::rateLimitGroup('/auth/mfa/factors', $limits->mfaEnroll, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/totp/confirm', $limits->mfaConfirm, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/totp/enroll', $limits->mfaEnroll, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/sms/confirm', $limits->mfaConfirm, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/email/confirm', $limits->mfaConfirm, $cache, $responseFactory),
                // SMS/email enroll *sends* a code — throttle harder (cost + OTP-bombing).
                self::rateLimitGroup('/auth/mfa/sms/enroll', $limits->mfaSend, $cache, $responseFactory),
                self::rateLimitGroup('/auth/mfa/email/enroll', $limits->mfaSend, $cache, $responseFactory),
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
}
