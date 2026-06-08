<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests;

use Altair\Container\Container;
use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Contracts\TokenValidatorInterface;
use Altair\Module\Migration\MigrationSource;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Contracts\PasswordHasherInterface;
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
use Univeros\Polaris\Identity\EmailVerificationService;
use Univeros\Polaris\Identity\LoginService;
use Univeros\Polaris\Identity\PasswordResetService;
use Univeros\Polaris\Identity\RegistrationService;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Module;

use function putenv;

final class ModuleTest extends TestCase
{
    protected function setUp(): void
    {
        putenv('APP_KEY=dGVzdC1hcHAta2V5LTAwMDAwMDAwMDAwMDAwMDA=');
        putenv('AUTH_JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----');
        putenv('AUTH_JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----');
    }

    protected function tearDown(): void
    {
        foreach (['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_JWT_KID', 'AUTH_ISSUER', 'AUTH_AUDIENCE'] as $key) {
            putenv($key);
        }
    }

    public function testNameIsTheModulePackage(): void
    {
        self::assertSame('univeros/polaris', (new Module())->name());
    }

    public function testApplyBindsValidatedConfigAndSecrets(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        self::assertInstanceOf(AuthConfig::class, $container->get(AuthConfig::class));
        self::assertInstanceOf(Secrets::class, $container->get(Secrets::class));
    }

    public function testApplyBindsTheIdentityProviderAndCredentialValidator(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        self::assertTrue($container->has(IdentityProviderInterface::class));
        self::assertTrue($container->has(IdentityValidatorInterface::class));
    }

    public function testApplyFailsFastWhenSecretsAreMissing(): void
    {
        putenv('APP_KEY');
        putenv('AUTH_JWT_PRIVATE_KEY');
        putenv('AUTH_JWT_PUBLIC_KEY');

        $this->expectException(InvalidConfigException::class);

        (new Module())->apply(new Container());
    }

    public function testApplyBindsTheTokenMachinery(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        $tokenBindings = [
            TokenConfigurationInterface::class,
            TokenGeneratorInterface::class,
            TokenParserInterface::class,
            TokenValidatorInterface::class,
            TokenFactoryInterface::class,
        ];

        foreach ($tokenBindings as $id) {
            self::assertTrue($container->has($id), "$id should be bound");
        }
    }

    public function testContributesTheJwksRoute(): void
    {
        self::assertContains(
            ['GET', '/auth/.well-known/jwks.json', JwksDomain::class],
            (new Module())->routes(),
        );
    }

    public function testContributesTheRegistrationRoutes(): void
    {
        $routes = (new Module())->routes();

        self::assertContains(['POST', '/auth/register', RegisterDomain::class], $routes);
        self::assertContains(['POST', '/auth/email/verify', VerifyEmailDomain::class], $routes);
        self::assertContains(['POST', '/auth/email/verify/resend', ResendVerificationDomain::class], $routes);
        self::assertContains(['POST', '/auth/login', LoginDomain::class], $routes);
    }

    public function testApplyBindsTheLoginService(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        self::assertTrue($container->has(LoginService::class));
        self::assertTrue($container->has(LoginDomain::class));
    }

    public function testContributesTheSessionRoutes(): void
    {
        $routes = (new Module())->routes();

        self::assertContains(['POST', '/auth/token/refresh', RefreshTokenDomain::class], $routes);
        self::assertContains(['POST', '/auth/logout', LogoutDomain::class], $routes);
        self::assertContains(['POST', '/auth/logout-all', LogoutAllDomain::class], $routes);
        self::assertContains(['GET', '/auth/sessions', SessionsDomain::class], $routes);
        self::assertContains(['DELETE', '/auth/sessions/{id}', RevokeSessionDomain::class], $routes);
    }

    public function testApplyBindsTheSessionService(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        self::assertTrue($container->has(SessionService::class));
        self::assertTrue($container->has(RefreshTokenDomain::class));
    }

    public function testContributesThePasswordAndProfileRoutes(): void
    {
        $routes = (new Module())->routes();

        self::assertContains(['POST', '/auth/password/forgot', ForgotPasswordDomain::class], $routes);
        self::assertContains(['POST', '/auth/password/reset', ResetPasswordDomain::class], $routes);
        self::assertContains(['POST', '/auth/password/change', ChangePasswordDomain::class], $routes);
        self::assertContains(['GET', '/auth/me', MeDomain::class], $routes);
    }

    public function testApplyBindsThePasswordResetService(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        self::assertTrue($container->has(PasswordResetService::class));
        self::assertTrue($container->has(MeDomain::class));
    }

    public function testApplyBindsTheRegistrationServices(): void
    {
        $container = new Container();
        (new Module())->apply($container);

        $bindings = [
            PasswordHasherInterface::class,
            RegistrationService::class,
            EmailVerificationService::class,
            RegisterDomain::class,
            VerifyEmailDomain::class,
            ResendVerificationDomain::class,
        ];

        foreach ($bindings as $id) {
            self::assertTrue($container->has($id), "$id should be bound");
        }
    }

    public function testEntityDirectoriesExist(): void
    {
        foreach ((new Module())->entityDirectories() as $directory) {
            self::assertDirectoryExists($directory);
        }
    }

    public function testMigrationDirectoriesExist(): void
    {
        foreach ((new Module())->migrationDirectories() as $source) {
            self::assertInstanceOf(MigrationSource::class, $source);
            self::assertDirectoryExists($source->directory);
        }
    }
}
