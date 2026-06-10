<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Container\Container;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Module\Contracts\EntityDirectoriesProviderInterface;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\Contracts\RoutesProviderInterface;
use Altair\Module\Migration\MigrationSource;
use Override;
use Univeros\Polaris\Bootstrap\HttpBindings;
use Univeros\Polaris\Bootstrap\IdentityBindings;
use Univeros\Polaris\Bootstrap\MfaBindings;
use Univeros\Polaris\Bootstrap\OrganizationBindings;
use Univeros\Polaris\Bootstrap\Routes;
use Univeros\Polaris\Bootstrap\SessionBindings;
use Univeros\Polaris\Bootstrap\TokenBindings;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Http\Middleware\AuthenticatedRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\AuthorizationMiddleware;
use Univeros\Polaris\Http\Middleware\AuthRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\ClientContextMiddleware;
use Univeros\Polaris\Http\Middleware\DenylistMiddleware;
use Univeros\Polaris\Http\Middleware\MfaTokenMiddleware;
use Univeros\Polaris\Http\Middleware\StepUpMiddleware;

use function getenv;
use function in_array;

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

        (new IdentityBindings())->apply($container);
        (new TokenBindings())->apply($container, $authConfig, $secrets);
        (new SessionBindings())->apply($container);
        (new HttpBindings())->apply($container);
        (new MfaBindings())->apply($container, $authConfig, $secrets);
        (new OrganizationBindings())->apply($container);
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
     * - {@see AuthorizationMiddleware} just after that, enforcing each Action's declared
     *   `REQUIRES_PERMISSIONS` before the action runs (a no-op on routes that declare none).
     *
     * @return list<array{middleware: class-string, priority: int}>
     */
    #[Override]
    public function middleware(): array
    {
        return [
            ['middleware' => AuthRateLimitMiddleware::class, 'priority' => MiddlewarePriority::EXCEPTION_HANDLER + 50],
            // Early in the pipeline: sanitize the User-Agent into a request attribute so every
            // domain's ClientContext (session rows, audit events #90) reads one bounded value.
            ['middleware' => ClientContextMiddleware::class, 'priority' => MiddlewarePriority::EXCEPTION_HANDLER + 49],
            ['middleware' => TokenAuthenticationMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 5],
            // In the (DISPATCHER, ACTION) band: runs after routing resolves the gate route and before
            // the action runs, so the validated ticket is attached before the gate domain reads it.
            // Path-scoped, so it no-ops on every other route.
            ['middleware' => MfaTokenMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 4],
            // After the access-token middleware (so the token is attached) and before the action, it
            // gates the step-up routes on a recent auth_time. Path-scoped; no-op elsewhere.
            ['middleware' => StepUpMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 6],
            // After the access-token middleware attaches the token: optional instant revocation
            // check (one cache read; a no-op when security.access_token.denylist is off).
            ['middleware' => DenylistMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 7],
            // After token auth (so `sub` is trustworthy): the global per-user budget across all
            // authenticated endpoints (#97). No-op on unauthenticated requests.
            ['middleware' => AuthenticatedRateLimitMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 8],
            // After routing + token auth, before the action: enforce each Action's declared
            // REQUIRES_PERMISSIONS (rbac.md §5a). No-op on routes that declare none.
            ['middleware' => AuthorizationMiddleware::class, 'priority' => MiddlewarePriority::DISPATCHER + 10],
        ];
    }

    /**
     * @return list<array{0: string, 1: string, 2: class-string}>
     */
    #[Override]
    public function routes(): array
    {
        return Routes::table();
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

        $flag = static fn(string $key): bool => in_array(getenv($key), ['1', 'true', 'on'], true);

        return [
            'issuer' => $issuer !== false && $issuer !== '' ? $issuer : 'univeros/polaris',
            'audience' => $audience !== false && $audience !== '' ? $audience : null,
            'access_token' => ['denylist' => $flag('AUTH_ACCESS_TOKEN_DENYLIST')],
            'password' => ['breach_check' => $flag('AUTH_PASSWORD_BREACH_CHECK')],
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
        foreach (
            [
            'APP_KEY',
            'AUTH_JWT_PRIVATE_KEY',
            'AUTH_JWT_PUBLIC_KEY',
            'AUTH_JWT_KID',
            'AUTH_JWT_PREVIOUS_PUBLIC_KEY',
            'AUTH_JWT_PREVIOUS_KID',
            ] as $key
        ) {
            $value = getenv($key);
            if ($value !== false) {
                $env[$key] = $value;
            }
        }

        return $env;
    }
}
