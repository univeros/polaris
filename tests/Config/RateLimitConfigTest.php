<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Config;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Config\RateLimitConfig;

final class RateLimitConfigTest extends TestCase
{
    public function testDefaultsMatchTheSecuritySpec(): void
    {
        $config = RateLimitConfig::defaults();

        self::assertSame(10, $config->login->limit);
        self::assertSame(300, $config->login->windowSeconds);

        self::assertSame(5, $config->register->limit);
        self::assertSame(3600, $config->register->windowSeconds);

        self::assertSame(5, $config->passwordForgot->limit);
        self::assertSame(3600, $config->passwordForgot->windowSeconds);

        self::assertSame(60, $config->tokenRefresh->limit);
        self::assertSame(60, $config->tokenRefresh->windowSeconds);
    }

    public function testEachGroupHasADistinctCacheKeyPrefix(): void
    {
        $config = RateLimitConfig::defaults();

        $prefixes = [
            $config->login->keyPrefix,
            $config->register->keyPrefix,
            $config->passwordForgot->keyPrefix,
            $config->tokenRefresh->keyPrefix,
        ];

        self::assertSame($prefixes, array_unique($prefixes), 'prefixes must not collide in a shared cache');
    }

    public function testFromArrayOverridesOnlyTheProvidedGroups(): void
    {
        $config = RateLimitConfig::fromArray([
            'login' => ['limit' => 3, 'window' => 60],
        ]);

        self::assertSame(3, $config->login->limit);
        self::assertSame(60, $config->login->windowSeconds);
        // Untouched groups keep their defaults.
        self::assertSame(5, $config->register->limit);
    }

    public function testFromArrayRejectsANonPositiveBudget(): void
    {
        $this->expectException(InvalidArgumentException::class);

        RateLimitConfig::fromArray(['login' => ['limit' => 0]]);
    }
}
