<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Http\NullIdentityValidator;

final class NullIdentityValidatorTest extends TestCase
{
    public function testNeverValidatesCredentials(): void
    {
        // Login is the sole credential entry point; the framework middleware must never mint a token.
        self::assertFalse((new NullIdentityValidator())(['user' => 'ada@example.com', 'password' => 'secret']));
    }
}
