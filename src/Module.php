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
use Altair\Http\Jwt\LcobucciTokenParser;
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
use Altair\Observability\Contracts\RecorderInterface;
use Altair\Observability\Metrics\Meter;
use Altair\Observability\Recorder\InMemoryRecorder;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Cycle\ORM\ORMInterface;
use Altair\Security\Contracts\EncrypterInterface;
use Altair\Security\Encrypter;
use Altair\Security\Support\HkdfKey;
use Override;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Authorization\EscalationGuard;
use Univeros\Polaris\Authorization\Gate;
use Univeros\Polaris\Authorization\InvitationService;
use Univeros\Polaris\Authorization\MembershipService;
use Univeros\Polaris\Authorization\OrganizationService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Authorization\RoleService;
use Univeros\Polaris\Authorization\RbacSessionPrincipalResolver;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Config\RateLimitConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Config\TotpConfig;
use Univeros\Polaris\Contracts\BreachedPasswordCheckInterface;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Event\NullEventDispatcher;
use Univeros\Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Http\Auth\ChangePasswordDomain;
use Univeros\Polaris\Http\Auth\DeleteFactorDomain;
use Univeros\Polaris\Http\Auth\EmailEnrollDomain;
use Univeros\Polaris\Http\Auth\ForgotPasswordDomain;
use Univeros\Polaris\Http\Auth\LoginDomain;
use Univeros\Polaris\Http\Auth\LogoutAllDomain;
use Univeros\Polaris\Http\Auth\LogoutDomain;
use Univeros\Polaris\Http\Auth\MeDomain;
use Univeros\Polaris\Http\Auth\MfaChallengeDomain;
use Univeros\Polaris\Http\Auth\MfaFactorsDomain;
use Univeros\Polaris\Http\Auth\MfaVerifyDomain;
use Univeros\Polaris\Http\Auth\OtpFactorConfirmDomain;
use Univeros\Polaris\Http\Auth\RefreshTokenDomain;
use Univeros\Polaris\Http\Auth\RegenerateRecoveryCodesDomain;
use Univeros\Polaris\Http\Auth\RegisterDomain;
use Univeros\Polaris\Http\Auth\ResendVerificationDomain;
use Univeros\Polaris\Http\Auth\ResetPasswordDomain;
use Univeros\Polaris\Http\Auth\RevokeSessionDomain;
use Univeros\Polaris\Http\Auth\SessionsDomain;
use Univeros\Polaris\Http\Auth\SmsEnrollDomain;
use Univeros\Polaris\Http\Auth\StepUpChallengeDomain;
use Univeros\Polaris\Http\Auth\StepUpVerifyDomain;
use Univeros\Polaris\Http\Auth\AcceptInviteDomain;
use Univeros\Polaris\Http\Auth\SwitchOrgDomain;
use Univeros\Polaris\Http\Auth\TotpConfirmDomain;
use Univeros\Polaris\Http\Auth\UpdateFactorDomain;
use Univeros\Polaris\Http\Auth\TotpEnrollDomain;
use Univeros\Polaris\Http\Auth\VerifyEmailDomain;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Univeros\Polaris\Http\Middleware\AuthenticatedRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\AuthorizationMiddleware;
use Univeros\Polaris\Http\Middleware\AuthRateLimitMiddleware;
use Univeros\Polaris\Http\Middleware\BearerTokenExtractor;
use Univeros\Polaris\Http\Middleware\TokenSubjectKeyResolver;
use Univeros\Polaris\Http\Middleware\DenylistMiddleware;
use Univeros\Polaris\Http\Middleware\MfaTokenMiddleware;
use Univeros\Polaris\Http\Middleware\NullCredentialsExtractor;
use Univeros\Polaris\Http\Middleware\RateLimitGroup;
use Univeros\Polaris\Http\Middleware\StepUpMiddleware;
use Univeros\Polaris\Http\Middleware\UnauthorizedResponder;
use Univeros\Polaris\Http\Orgs\ChangeMemberRolesDomain;
use Univeros\Polaris\Http\Orgs\ChangeMemberStatusDomain;
use Univeros\Polaris\Http\Orgs\CreateOrganizationDomain;
use Univeros\Polaris\Http\Orgs\CreateInviteDomain;
use Univeros\Polaris\Http\Orgs\CreateRoleDomain;
use Univeros\Polaris\Http\Orgs\DeleteOrganizationDomain;
use Univeros\Polaris\Http\Orgs\DeleteRoleDomain;
use Univeros\Polaris\Http\Orgs\ListInvitesDomain;
use Univeros\Polaris\Http\Orgs\ListMembersDomain;
use Univeros\Polaris\Http\Orgs\ListPermissionsDomain;
use Univeros\Polaris\Http\Orgs\ListRolesDomain;
use Univeros\Polaris\Http\Orgs\RevokeInviteDomain;
use Univeros\Polaris\Http\Orgs\UpdateOrganizationDomain;
use Univeros\Polaris\Http\Orgs\UpdateRoleDomain;
use Univeros\Polaris\Http\Users\DeleteUserDomain;
use Univeros\Polaris\Http\Users\DisableUserDomain;
use Univeros\Polaris\Http\Users\EnableUserDomain;
use Univeros\Polaris\Http\Users\ReadUserDomain;
use Univeros\Polaris\Http\Users\UpdateUserDomain;
use Univeros\Polaris\Http\Orgs\ListOrganizationsDomain;
use Univeros\Polaris\Http\Orgs\ReadOrganizationDomain;
use Univeros\Polaris\Http\Orgs\RemoveMemberDomain;
use Univeros\Polaris\Http\Rule\AnyRule;
use Univeros\Polaris\Http\Rule\MethodPathRule;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Identity\EmailVerificationService;
use Univeros\Polaris\Identity\LoginService;
use Univeros\Polaris\Identity\MfaLoginService;
use Univeros\Polaris\Identity\PasswordPolicy;
use Univeros\Polaris\Identity\PasswordResetService;
use Univeros\Polaris\Identity\RegistrationService;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Identity\UserAdminService;
use Univeros\Polaris\Identity\StepUpService;
use Univeros\Polaris\Maintenance\PruneExpiredService;
use Univeros\Polaris\Mfa\EndroidQrRenderer;
use Univeros\Polaris\Notification\NotificationListener;
use Univeros\Polaris\Observability\AuditLogListener;
use Univeros\Polaris\Observability\MetricsListener;
use Univeros\Polaris\Mfa\LogOtpMailer;
use Univeros\Polaris\Mfa\LogSmsSender;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;
use Univeros\Polaris\Mfa\MfaConfirmation;
use Univeros\Polaris\Mfa\MfaEnforcement;
use Univeros\Polaris\Mfa\MfaManagementService;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Mfa\OtpFactorService;
use Univeros\Polaris\Mfa\OtphpTotpProvider;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Persistence\EmailVerificationRepository;
use Univeros\Polaris\Security\NullBreachedPasswordCheck;
use Univeros\Polaris\Token\AccessTokenDenylist;
use Univeros\Polaris\Persistence\InvitationRepository;
use Univeros\Polaris\Persistence\MembershipRepository;
use Univeros\Polaris\Persistence\MembershipRoleRepository;
use Univeros\Polaris\Persistence\MfaFactorRepository;
use Univeros\Polaris\Persistence\OrganizationRepository;
use Univeros\Polaris\Persistence\OtpChallengeRepository;
use Univeros\Polaris\Persistence\PasswordResetRepository;
use Univeros\Polaris\Persistence\PermissionRepository;
use Univeros\Polaris\Persistence\RecoveryCodeRepository;
use Univeros\Polaris\Persistence\RefreshTokenRepository;
use Univeros\Polaris\Persistence\RolePermissionRepository;
use Univeros\Polaris\Persistence\RoleRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Argon2idPasswordHasher;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Support\InMemoryCache;
use Univeros\Polaris\Token\JwtSignerFactory;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Token\PolarisTokenFactory;
use Univeros\Polaris\Token\PolarisTokenGenerator;
use Univeros\Polaris\Token\PolarisTokenParser;
use Univeros\Polaris\Token\PolarisTokenValidator;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

use function array_map;
use function getenv;
use function in_array;
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
        // The MFA-gate routes carry the single-purpose `login_mfa` ticket, not an access token, so
        // they bypass the access-token middleware; {@see MfaTokenMiddleware} authenticates them.
        '/auth/mfa/challenge',
        '/auth/mfa/verify',
    ];

    /**
     * Sensitive routes that require a recent strong authentication (spec §7). {@see StepUpMiddleware}
     * enforces `now - auth_time <= step_up.max_age` on these — but only for users who have a
     * confirmed factor — and returns `401 step_up_required` when stale. Matched as path prefixes.
     */
    private const array STEP_UP_PATHS = [
        '/auth/password/change',
        '/auth/mfa/recovery-codes/regenerate',
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
        $this->bindTotpEnrollment($container, $secrets);
        $this->bindMfaLogin($container, $authConfig, $secrets);
        $this->bindStepUp($container);
        $this->bindMfaManagement($container);
        $this->bindOrganizations($container);
    }

    /**
     * Bind TOTP enrollment: a secret-at-rest {@see EncrypterInterface} (a {@see Encrypter} over an
     * {@see HkdfKey} derived from the application key with a distinct context, AES-256-CBC), the
     * {@see RecoveryCodeService}, the {@see MfaTotpService}, and the enroll/confirm domains. The
     * repositories the service depends on are plain Cycle repositories the container autowires.
     */
    private function bindTotpEnrollment(Container $container, Secrets $secrets): void
    {
        if (!$container->has(EncrypterInterface::class)) {
            $appKey = $secrets->appKey;
            $container->singleton(
                EncrypterInterface::class,
                // The default `$allowedClasses = false` MUST stay: TOTP secrets are plain strings, so
                // decrypt() must never reconstruct objects (no unserialize gadget surface).
                static fn(): Encrypter => new Encrypter(
                    new HkdfKey(
                        $appKey,
                        null,
                        'polaris:encrypter:mfa',
                        EncrypterInterface::AES_256_CBC_CIPHER_KEY_LENGTH,
                    ),
                    EncrypterInterface::AES_256_CBC_CIPHER,
                ),
            );
        }

        $container->singleton(
            RecoveryCodeService::class,
            static fn(
                ORMInterface $orm,
                RecoveryCodeRepository $codes,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): RecoveryCodeService => new RecoveryCodeService($codes, $unitOfWork, $pepper, $clock, $events, $orm),
        );
        $container->singleton(
            MfaConfirmation::class,
            static fn(
                MfaFactorRepository $factors,
                RecoveryCodeService $recoveryCodes,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): MfaConfirmation => new MfaConfirmation($factors, $recoveryCodes, $unitOfWork, $clock, $events),
        );
        $container->singleton(
            MfaTotpService::class,
            static fn(
                MfaFactorRepository $factors,
                TotpProviderInterface $totp,
                EncrypterInterface $encrypter,
                QrCodeRendererInterface $qr,
                MfaConfirmation $confirmation,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
            ): MfaTotpService => new MfaTotpService(
                $factors,
                $totp,
                $encrypter,
                $qr,
                $confirmation,
                $unitOfWork,
                $clock,
            ),
        );
        $container->singleton(
            OtpFactorService::class,
            static fn(
                MfaFactorRepository $factors,
                OtpService $otp,
                MfaConfirmation $confirmation,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
            ): OtpFactorService => new OtpFactorService($factors, $otp, $confirmation, $unitOfWork, $clock),
        );
        $container->singleton(TotpEnrollDomain::class);
        $container->singleton(TotpConfirmDomain::class);
        $container->singleton(SmsEnrollDomain::class);
        $container->singleton(EmailEnrollDomain::class);
        $container->singleton(OtpFactorConfirmDomain::class);
    }

    /**
     * Bind the login MFA gate (#23): the short-lived `login_mfa` ticket service, the
     * {@see MfaLoginService} that lists factors / challenges / verifies and mints the real session,
     * the gate domains, and the {@see MfaTokenMiddleware} that authenticates the ticket on those
     * routes.
     *
     * The ticket is signed with the access-token key set but minted by a **separate** generator
     * whose configuration carries a short TTL (`auth.mfa.login_token_ttl`); it is validated by the
     * framework {@see LcobucciTokenParser} (the access-token {@see PolarisTokenParser} would reject
     * its `purpose` claim — which is exactly what keeps the ticket off normal routes).
     */
    private function bindMfaLogin(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $keyId = $secrets->jwtKid;
        $container->singleton(
            MfaLoginTokenService::class,
            static function (
                TokenConfigurationInterface $config,
                ClockInterface $clock,
            ) use (
                $authConfig,
                $secrets,
                $keyId
            ): MfaLoginTokenService {
                $ticketConfig = new TokenConfiguration(
                    $secrets->jwtPublicKey,
                    $authConfig->mfaLoginTokenTtl,
                    JwtSignerFactory::create($authConfig->accessToken->signer),
                    $authConfig->issuer,
                    null,
                    $secrets->jwtPrivateKey,
                    $authConfig->audience,
                );

                return new MfaLoginTokenService(
                    new PolarisTokenGenerator($ticketConfig, $clock, $keyId),
                    new LcobucciTokenParser($config, $clock),
                );
            },
        );

        $container->singleton(
            MfaChallengeVerifier::class,
            static fn(
                MfaFactorRepository $factors,
                MfaTotpService $totp,
                OtpService $otp,
                RecoveryCodeService $recovery,
            ): MfaChallengeVerifier => new MfaChallengeVerifier($factors, $totp, $otp, $recovery),
        );

        $container->singleton(
            MfaLoginService::class,
            static fn(
                MfaChallengeVerifier $verifier,
                MfaLoginTokenService $tickets,
                TokenService $tokens,
                SessionPrincipalResolverInterface $principals,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): MfaLoginService => new MfaLoginService(
                $verifier,
                $tickets,
                $tokens,
                $principals,
                $clock,
                $events,
            ),
        );

        $container->singleton(MfaChallengeDomain::class);
        $container->singleton(MfaVerifyDomain::class);

        $container->singleton(
            MfaTokenMiddleware::class,
            static fn(
                MfaLoginTokenService $tickets,
                ResponseFactoryInterface $responseFactory,
            ): MfaTokenMiddleware => new MfaTokenMiddleware(
                new RequestPathRule(['path' => [
                    preg_quote('/auth/mfa/challenge', '@'),
                    preg_quote('/auth/mfa/verify', '@'),
                ]]),
                new BearerTokenExtractor(),
                $tickets,
                $responseFactory,
            ),
        );
    }

    /**
     * Bind step-up re-authentication (#25): the {@see StepUpService} (re-verify a factor and mint a
     * refreshed access token for the existing session), its challenge/verify domains, the step-up-
     * gated recovery-codes regenerate domain, and the {@see StepUpMiddleware} that returns
     * `401 step_up_required` on the {@see self::STEP_UP_PATHS} when the session's `auth_time` is stale.
     */
    private function bindStepUp(Container $container): void
    {
        $container->singleton(
            StepUpService::class,
            static fn(
                MfaChallengeVerifier $verifier,
                TokenService $tokens,
                EventDispatcherInterface $events,
            ): StepUpService => new StepUpService($verifier, $tokens, $events),
        );

        $container->singleton(StepUpChallengeDomain::class);
        $container->singleton(StepUpVerifyDomain::class);
        $container->singleton(RegenerateRecoveryCodesDomain::class);

        $container->singleton(
            StepUpMiddleware::class,
            static fn(
                MfaChallengeVerifier $verifier,
                AuthConfig $config,
                ClockInterface $clock,
                ResponseFactoryInterface $responseFactory,
            ): StepUpMiddleware => new StepUpMiddleware(
                new AnyRule(
                    new RequestPathRule(['path' => array_map(
                        static fn(string $path): string => preg_quote($path, '@'),
                        self::STEP_UP_PATHS,
                    )]),
                    // Removing a factor needs step-up too, but the path is shared with the GET list and
                    // the PATCH — so gate it by method, not prefix.
                    new MethodPathRule('DELETE', new RequestPathRule(['path' => [preg_quote('/auth/mfa/factors', '@')]])),
                    // Account deletion (self or admin) and disabling a user are sensitive (#37);
                    // the /users prefix is shared with reads, so gate by method/sub-path. The
                    // disable pattern is deliberately NOT preg_quote()d: `[^/]+` must stay a live
                    // regex fragment so it matches the {id} segment.
                    new MethodPathRule('DELETE', new RequestPathRule(['path' => [preg_quote('/users', '@')]])),
                    new MethodPathRule('POST', new RequestPathRule(['path' => ['/users/[^/]+/disable']])),
                    // Org deletion (#78) needs step-up, but DELETE /orgs/{id}/members|invites|roles
                    // sub-paths must not. The rule wraps patterns as `@^…(/.*)?$@`, so the
                    // lookahead `(?!.)` pins the match to the {id} segment (tolerating one
                    // trailing slash) while any deeper path fails. Deliberately not preg_quote()d.
                    new MethodPathRule('DELETE', new RequestPathRule(['path' => ['/orgs/[^/]+/?(?!.)']])),
                ),
                $verifier,
                $config,
                $clock,
                $responseFactory,
            ),
        );
    }

    /**
     * Bind MFA factor management (#26): {@see MfaEnforcement} (is MFA required for this user?),
     * {@see MfaManagementService} (list / relabel / re-default / remove, blocking the last confirmed
     * factor when enforced), and the list/patch/delete domains.
     */
    private function bindMfaManagement(Container $container): void
    {
        $container->singleton(
            MfaEnforcement::class,
            static fn(UserRepository $users, AuthConfig $config): MfaEnforcement => new MfaEnforcement($users, $config),
        );
        $container->singleton(
            MfaManagementService::class,
            static fn(
                MfaFactorRepository $factors,
                MfaEnforcement $enforcement,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): MfaManagementService => new MfaManagementService($factors, $enforcement, $unitOfWork, $clock, $events),
        );

        $container->singleton(MfaFactorsDomain::class);
        $container->singleton(UpdateFactorDomain::class);
        $container->singleton(DeleteFactorDomain::class);
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
        $container->singleton(
            OtpConfig::class,
            static fn(AuthConfig $config): OtpConfig => $config->otp,
        );

        $this->bindIfAbsent($container, SmsSenderInterface::class, LogSmsSender::class);
        $this->bindIfAbsent($container, OtpMailerInterface::class, LogOtpMailer::class);
        $this->bindIfAbsent($container, TotpProviderInterface::class, OtphpTotpProvider::class);
        $this->bindIfAbsent($container, QrCodeRendererInterface::class, EndroidQrRenderer::class);

        $container->singleton(
            OtpService::class,
            static fn(
                ORMInterface $orm,
                OtpChallengeRepository $challenges,
                SmsSenderInterface $sms,
                OtpMailerInterface $mailer,
                Pepper $pepper,
                OtpConfig $config,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
                CacheInterface $cache,
            ): OtpService => new OtpService(
                $challenges,
                $sms,
                $mailer,
                $pepper,
                $config,
                $unitOfWork,
                $clock,
                $events,
                $cache,
                $orm,
            ),
        );
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
                AccessTokenDenylist $denylist,
            ): SessionService => new SessionService($refreshTokens, $tokens, $clock, $events, $denylist),
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
                MfaLoginService $mfaLogin,
                UnitOfWorkInterface $unitOfWork,
                AuthConfig $config,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): LoginService => new LoginService(
                $users,
                $hasher,
                $tokens,
                $mfaLogin,
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
        if (!$container->has(BreachedPasswordCheckInterface::class)) {
            // Hosts enable real screening by binding the HIBP adapter (or their own) and turning
            // on auth.password.breach_check; the default is an always-clean no-op.
            $container->singleton(BreachedPasswordCheckInterface::class, NullBreachedPasswordCheck::class);
        }
        $container->singleton(
            PasswordPolicy::class,
            static fn(AuthConfig $config, BreachedPasswordCheckInterface $breaches): PasswordPolicy
                => new PasswordPolicy(
                    $config->passwordMinLength,
                    $config->breachCheck ? $breaches : null,
                ),
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
     * no-op PSR-14 dispatcher (until the host wires listeners in Phase 4), the
     * {@see PermissionResolver} and the {@see RbacSessionPrincipalResolver} (which embeds the active
     * org's roles/scope into issued tokens), the {@see SwitchOrgDomain}, and {@see TokenService},
     * which issues and rotates refresh tokens with reuse detection.
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
            PermissionResolver::class,
            static fn(
                UserRepository $users,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
            ): PermissionResolver => new PermissionResolver(
                $users,
                $organizations,
                $memberships,
                $membershipRoles,
                $roles,
                $rolePermissions,
                $permissions,
            ),
        );

        // The RBAC resolver replaces the Phase-1 default: it embeds the user's roles (and, when
        // access_token.embed_scope is on, the flattened permission scope) for the active org.
        $container->singleton(
            SessionPrincipalResolverInterface::class,
            static fn(
                UserRepository $users,
                PermissionResolver $permissions,
                AuthConfig $config,
            ): RbacSessionPrincipalResolver => new RbacSessionPrincipalResolver($users, $permissions, $config),
        );

        $container->singleton(
            SwitchOrgDomain::class,
            static fn(
                TokenService $tokens,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                AuthConfig $config,
            ): SwitchOrgDomain => new SwitchOrgDomain($tokens, $organizations, $memberships, $config),
        );

        $container->singleton(
            TokenService::class,
            static fn(
                ORMInterface $orm,
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
                $orm,
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
     * Bind the organization service — a transactional create that clones the owner/admin/member
     * system role templates into org-scoped roles and grants the creator an active `owner`
     * membership — plus the `/orgs` domains. The repositories are autowired; the
     * {@see PermissionCatalog} is bound with no host contributors by default (a host may rebind it).
     */
    private function bindOrganizations(Container $container): void
    {
        $container->singleton(PermissionCatalog::class, static fn(): PermissionCatalog => new PermissionCatalog());

        $container->singleton(
            OrganizationService::class,
            static fn(
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                PermissionRepository $permissions,
                PermissionCatalog $catalog,
                SessionService $sessions,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): OrganizationService => new OrganizationService(
                $organizations,
                $memberships,
                $permissions,
                $catalog,
                $sessions,
                $unitOfWork,
                $clock,
                $events,
            ),
        );

        $container->singleton(CreateOrganizationDomain::class);
        $container->singleton(ListOrganizationsDomain::class);
        $container->singleton(
            ReadOrganizationDomain::class,
            static fn(OrganizationRepository $organizations): ReadOrganizationDomain
                => new ReadOrganizationDomain($organizations),
        );
        $container->singleton(UpdateOrganizationDomain::class);
        $container->singleton(DeleteOrganizationDomain::class);

        $container->singleton(
            EscalationGuard::class,
            static fn(
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
            ): EscalationGuard => new EscalationGuard($rolePermissions, $permissions),
        );

        $container->singleton(
            MembershipService::class,
            static fn(
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                UserRepository $users,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                SessionService $sessions,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): MembershipService => new MembershipService(
                $memberships,
                $membershipRoles,
                $roles,
                $users,
                $resolver,
                $escalation,
                $unitOfWork,
                $sessions,
                $clock,
                $events,
            ),
        );
        $container->singleton(ListMembersDomain::class);
        $container->singleton(ChangeMemberRolesDomain::class);
        $container->singleton(ChangeMemberStatusDomain::class);
        $container->singleton(RemoveMemberDomain::class);

        $container->singleton(
            InvitationService::class,
            static fn(
                InvitationRepository $invitations,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                UserRepository $users,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): InvitationService => new InvitationService(
                $invitations,
                $organizations,
                $memberships,
                $membershipRoles,
                $roles,
                $users,
                $resolver,
                $escalation,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );
        $container->singleton(CreateInviteDomain::class);
        $container->singleton(ListInvitesDomain::class);
        $container->singleton(RevokeInviteDomain::class);
        $container->singleton(AcceptInviteDomain::class);

        $container->singleton(
            RoleService::class,
            static fn(
                RoleRepository $roles,
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
            ): RoleService => new RoleService(
                $roles,
                $rolePermissions,
                $permissions,
                $resolver,
                $escalation,
                $unitOfWork,
                $clock,
            ),
        );
        $container->singleton(ListRolesDomain::class);
        $container->singleton(CreateRoleDomain::class);
        $container->singleton(UpdateRoleDomain::class);
        $container->singleton(DeleteRoleDomain::class);
        $container->singleton(ListPermissionsDomain::class);

        $container->singleton(
            UserAdminService::class,
            static fn(
                UserRepository $users,
                MfaFactorRepository $mfaFactors,
                OtpChallengeRepository $otpChallenges,
                EmailVerificationRepository $emailVerifications,
                PasswordResetRepository $passwordResets,
                PermissionResolver $resolver,
                SessionService $sessions,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): UserAdminService => new UserAdminService(
                $users,
                $mfaFactors,
                $otpChallenges,
                $emailVerifications,
                $passwordResets,
                $resolver,
                $sessions,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );
        $container->singleton(ReadUserDomain::class);
        $container->singleton(UpdateUserDomain::class);
        $container->singleton(DisableUserDomain::class);
        $container->singleton(EnableUserDomain::class);
        $container->singleton(DeleteUserDomain::class);
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
            ['POST', '/auth/switch-org', SwitchOrgDomain::class],
            ['GET', '/auth/sessions', SessionsDomain::class],
            ['DELETE', '/auth/sessions/{id}', RevokeSessionDomain::class],
            ['POST', '/auth/password/forgot', ForgotPasswordDomain::class],
            ['POST', '/auth/password/reset', ResetPasswordDomain::class],
            ['POST', '/auth/password/change', ChangePasswordDomain::class],
            ['GET', '/auth/me', MeDomain::class],
            ['POST', '/auth/mfa/totp/enroll', TotpEnrollDomain::class],
            ['POST', '/auth/mfa/totp/confirm', TotpConfirmDomain::class],
            ['POST', '/auth/mfa/sms/enroll', SmsEnrollDomain::class],
            ['POST', '/auth/mfa/sms/confirm', OtpFactorConfirmDomain::class],
            ['POST', '/auth/mfa/email/enroll', EmailEnrollDomain::class],
            ['POST', '/auth/mfa/email/confirm', OtpFactorConfirmDomain::class],
            ['POST', '/auth/mfa/challenge', MfaChallengeDomain::class],
            ['POST', '/auth/mfa/verify', MfaVerifyDomain::class],
            ['POST', '/auth/mfa/step-up/challenge', StepUpChallengeDomain::class],
            ['POST', '/auth/mfa/step-up', StepUpVerifyDomain::class],
            ['POST', '/auth/mfa/recovery-codes/regenerate', RegenerateRecoveryCodesDomain::class],
            ['GET', '/auth/mfa/factors', MfaFactorsDomain::class],
            ['PATCH', '/auth/mfa/factors/{id}', UpdateFactorDomain::class],
            ['DELETE', '/auth/mfa/factors/{id}', DeleteFactorDomain::class],
            ['POST', '/orgs', CreateOrganizationDomain::class],
            ['GET', '/orgs', ListOrganizationsDomain::class],
            ['GET', '/orgs/{id}', ReadOrganizationDomain::class],
            ['PATCH', '/orgs/{id}', UpdateOrganizationDomain::class],
            ['DELETE', '/orgs/{id}', DeleteOrganizationDomain::class],
            ['GET', '/orgs/{id}/members', ListMembersDomain::class],
            ['PATCH', '/orgs/{id}/members/{userId}/roles', ChangeMemberRolesDomain::class],
            ['PATCH', '/orgs/{id}/members/{userId}', ChangeMemberStatusDomain::class],
            ['DELETE', '/orgs/{id}/members/{userId}', RemoveMemberDomain::class],
            ['POST', '/orgs/{id}/invites', CreateInviteDomain::class],
            ['GET', '/orgs/{id}/invites', ListInvitesDomain::class],
            ['DELETE', '/orgs/{id}/invites/{inviteId}', RevokeInviteDomain::class],
            ['POST', '/auth/invites/accept', AcceptInviteDomain::class],
            ['GET', '/orgs/{id}/roles', ListRolesDomain::class],
            ['POST', '/orgs/{id}/roles', CreateRoleDomain::class],
            ['PATCH', '/orgs/{id}/roles/{roleId}', UpdateRoleDomain::class],
            ['DELETE', '/orgs/{id}/roles/{roleId}', DeleteRoleDomain::class],
            ['GET', '/permissions', ListPermissionsDomain::class],
            ['GET', '/users/{id}', ReadUserDomain::class],
            ['PATCH', '/users/{id}', UpdateUserDomain::class],
            ['POST', '/users/{id}/disable', DisableUserDomain::class],
            ['POST', '/users/{id}/enable', EnableUserDomain::class],
            ['DELETE', '/users/{id}', DeleteUserDomain::class],
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
