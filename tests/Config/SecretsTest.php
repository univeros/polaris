<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Config;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\Secrets;
use Univeros\Polaris\Exception\InvalidConfigException;

final class SecretsTest extends TestCase
{
    /**
     * @return array<string, string>
     */
    private function validEnv(): array
    {
        return [
            'APP_KEY' => 'app-key-value',
            'AUTH_JWT_PRIVATE_KEY' => 'private-key-pem',
            'AUTH_JWT_PUBLIC_KEY' => 'public-key-pem',
        ];
    }

    public function testBuildsFromCompleteEnvironment(): void
    {
        $secrets = Secrets::fromEnvironment($this->validEnv());

        self::assertSame('app-key-value', $secrets->appKey);
        self::assertSame('private-key-pem', $secrets->jwtPrivateKey);
        self::assertSame('public-key-pem', $secrets->jwtPublicKey);
        self::assertNotSame('', $secrets->jwtKid, 'a kid is derived from the public key when not supplied');
    }

    public function testUsesExplicitKidWhenProvided(): void
    {
        $secrets = Secrets::fromEnvironment($this->validEnv() + ['AUTH_JWT_KID' => 'key-2026']);

        self::assertSame('key-2026', $secrets->jwtKid);
    }

    public function testDerivesStableKidFromPublicKey(): void
    {
        $a = Secrets::fromEnvironment($this->validEnv());
        $b = Secrets::fromEnvironment($this->validEnv());

        self::assertSame($a->jwtKid, $b->jwtKid);
    }

    public function testRejectsMissingSecretsAndNamesThem(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('AUTH_JWT_PRIVATE_KEY');

        Secrets::fromEnvironment(['APP_KEY' => 'app-key-value']);
    }

    public function testTreatsBlankValuesAsMissing(): void
    {
        $this->expectException(InvalidConfigException::class);

        Secrets::fromEnvironment([
            'APP_KEY' => '   ',
            'AUTH_JWT_PRIVATE_KEY' => 'private-key-pem',
            'AUTH_JWT_PUBLIC_KEY' => 'public-key-pem',
        ]);
    }
}
