<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Validator\RepositoryIdentityValidator;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Contracts\BreachedPasswordCheckInterface;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
use Univeros\Polaris\Http\Auth\ChangePasswordDomain;
use Univeros\Polaris\Http\Auth\ForgotPasswordDomain;
use Univeros\Polaris\Http\Auth\LoginDomain;
use Univeros\Polaris\Http\Auth\MeDomain;
use Univeros\Polaris\Http\Auth\RegisterDomain;
use Univeros\Polaris\Http\Auth\ResendVerificationDomain;
use Univeros\Polaris\Http\Auth\ResetPasswordDomain;
use Univeros\Polaris\Http\Auth\VerifyEmailDomain;
use Univeros\Polaris\Identity\CycleIdentityProvider;
use Univeros\Polaris\Identity\EmailVerificationService;
use Univeros\Polaris\Identity\LoginService;
use Univeros\Polaris\Identity\MfaLoginService;
use Univeros\Polaris\Identity\PasswordPolicy;
use Univeros\Polaris\Identity\PasswordResetService;
use Univeros\Polaris\Identity\RegistrationService;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Persistence\EmailVerificationRepository;
use Univeros\Polaris\Persistence\PasswordResetRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Argon2idPasswordHasher;
use Univeros\Polaris\Security\NullBreachedPasswordCheck;
use Univeros\Polaris\Security\Pepper;
use Univeros\Polaris\Token\TokenService;

/**
 * Wires the identity machinery: the framework's auth contracts over the user store,
 * registration + email verification, password login, and password reset/change.
 */
final class IdentityBindings
{
    public function apply(Container $container): void
    {
        $this->bindIdentity($container);
        $this->bindRegistration($container);
        $this->bindLogin($container);
        $this->bindPasswordReset($container);
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
}
