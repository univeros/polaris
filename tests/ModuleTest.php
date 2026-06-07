<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests;

use Altair\Container\Container;
use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Module\Migration\MigrationSource;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Exception\InvalidConfigException;
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

    public function testContributesNoRoutesYet(): void
    {
        self::assertSame([], (new Module())->routes());
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
