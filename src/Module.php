<?php

declare(strict_types=1);

namespace Univeros\Polaris;

use Altair\Container\Container;
use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Contracts\TokenValidatorInterface;
use Altair\Http\Jwt\SystemClock;
use Altair\Http\Support\TokenConfiguration;
use Altair\Http\Validator\RepositoryIdentityValidator;
use Altair\Module\Contracts\EntityDirectoriesProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\Contracts\RoutesProviderInterface;
use Altair\Module\Migration\MigrationSource;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Override;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Event\NullEventDispatcher;
use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Http\Auth\LoginDomain;
use Univeros\Polaris\Http\Auth\RegisterDomain;
use Univeros\Polaris\Http\Auth\ResendVerificationDomain;
use Univeros\Polaris\Http\Auth\VerifyEmailDomain;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Identity\EmailVerificationService;
use Univeros\Polaris\Identity\LoginService;
use Univeros\Polaris\Identity\PasswordPolicy;
use Univeros\Polaris\Identity\RegistrationService;
use Univeros\Polaris\Persistence\EmailVerificationRepository;
use Univeros\Polaris\Persistence\RefreshTokenRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Argon2idPasswordHasher;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\DefaultSessionPrincipalResolver;
use Univeros\Polaris\Token\JwtSignerFactory;
use Univeros\Polaris\Token\PolarisTokenFactory;
use Univeros\Polaris\Token\PolarisTokenGenerator;
use Univeros\Polaris\Token\PolarisTokenParser;
use Univeros\Polaris\Token\PolarisTokenValidator;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

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
