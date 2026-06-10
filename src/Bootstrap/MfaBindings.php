<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Jwt\LcobucciTokenParser;
use Altair\Http\Rule\RequestPathRule;
use Altair\Http\Support\TokenConfiguration;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Security\Contracts\EncrypterInterface;
use Altair\Security\Encrypter;
use Altair\Security\Support\HkdfKey;
use Cycle\ORM\ORMInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\OtpConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Config\TotpConfig;
use Univeros\Polaris\Contracts\OtpMailerInterface;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;
use Univeros\Polaris\Contracts\SmsSenderInterface;
use Univeros\Polaris\Contracts\TotpProviderInterface;
use Univeros\Polaris\Http\Auth\DeleteFactorDomain;
use Univeros\Polaris\Http\Auth\EmailEnrollDomain;
use Univeros\Polaris\Http\Auth\MfaChallengeDomain;
use Univeros\Polaris\Http\Auth\MfaFactorsDomain;
use Univeros\Polaris\Http\Auth\MfaVerifyDomain;
use Univeros\Polaris\Http\Auth\OtpFactorConfirmDomain;
use Univeros\Polaris\Http\Auth\RegenerateRecoveryCodesDomain;
use Univeros\Polaris\Http\Auth\SmsEnrollDomain;
use Univeros\Polaris\Http\Auth\StepUpChallengeDomain;
use Univeros\Polaris\Http\Auth\StepUpVerifyDomain;
use Univeros\Polaris\Http\Auth\TotpConfirmDomain;
use Univeros\Polaris\Http\Auth\TotpEnrollDomain;
use Univeros\Polaris\Http\Auth\UpdateFactorDomain;
use Univeros\Polaris\Http\Middleware\BearerTokenExtractor;
use Univeros\Polaris\Http\Middleware\MfaTokenMiddleware;
use Univeros\Polaris\Http\Middleware\StepUpMiddleware;
use Univeros\Polaris\Http\Rule\AnyRule;
use Univeros\Polaris\Http\Rule\MethodPathRule;
use Univeros\Polaris\Identity\MfaLoginService;
use Univeros\Polaris\Identity\StepUpService;
use Univeros\Polaris\Mfa\EndroidQrRenderer;
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
use Univeros\Polaris\Persistence\MfaFactorRepository;
use Univeros\Polaris\Persistence\OtpChallengeRepository;
use Univeros\Polaris\Persistence\RecoveryCodeRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\JwtSignerFactory;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Token\PolarisTokenGenerator;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

use function array_map;
use function preg_quote;

/**
 * Wires the MFA machinery: the OTP/TOTP delivery ports and providers, TOTP/OTP factor
 * enrollment, the login MFA gate, step-up re-authentication, and factor management.
 */
final class MfaBindings
{
    /**
     * Sensitive routes that require a recent strong authentication (spec §7). {@see StepUpMiddleware}
     * enforces `now - auth_time <= step_up.max_age` on these — but only for users who have a
     * confirmed factor — and returns `401 step_up_required` when stale. Matched as path prefixes.
     */
    private const array STEP_UP_PATHS = [
        '/auth/password/change',
        '/auth/mfa/recovery-codes/regenerate',
    ];

    public function apply(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $this->bindMfaProviders($container);
        $this->bindTotpEnrollment($container, $secrets);
        $this->bindMfaLogin($container, $authConfig, $secrets);
        $this->bindStepUp($container);
        $this->bindMfaManagement($container);
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
}
