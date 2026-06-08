<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Http\Middleware\NullCredentialsExtractor;

final class NullCredentialsExtractorTest extends TestCase
{
    public function testNeverExtractsCredentials(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/auth/logout')
            ->withParsedBody(['username' => 'ada@example.com', 'password' => 'secret']);

        // Even a body that *looks* like credentials yields nothing: protected routes accept
        // only a pre-issued bearer token, so the middleware can never mint one from raw creds.
        self::assertNull((new NullCredentialsExtractor())->extract($request));
    }
}
