<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Container\Container;
use Altair\Module\Contracts\EntityDirectoriesProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\Contracts\RoutesProviderInterface;
use Altair\Module\Migration\MigrationSource;
use Override;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;

use function getenv;

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
     * eagerly so an invalid configuration or a missing secret fails at boot.
     */
    #[Override]
    public function apply(Container $container): void
    {
        $authConfig = AuthConfig::fromArray($this->authConfigArray());
        $secrets = Secrets::fromEnvironment($this->environment());

        $container->instance(AuthConfig::class, $authConfig);
        $container->instance(Secrets::class, $secrets);
    }

    /**
     * @return list<array{0: string, 1: string, 2: class-string}>
     */
    #[Override]
    public function routes(): array
    {
        // Endpoints are contributed by Phase 1+ (see docs/auth/api-reference.md).
        return [];
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
