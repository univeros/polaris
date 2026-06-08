<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Http\Middleware\BearerTokenExtractor;

final class BearerTokenExtractorTest extends TestCase
{
    public function testExtractsTheTokenAfterTheBearerScheme(): void
    {
        self::assertSame('abc.def.ghi', $this->extract('Bearer abc.def.ghi'));
    }

    public function testTheSchemeIsCaseInsensitive(): void
    {
        self::assertSame('abc.def.ghi', $this->extract('bearer abc.def.ghi'));
        self::assertSame('abc.def.ghi', $this->extract('BEARER abc.def.ghi'));
    }

    public function testCollapsesExtraWhitespaceAfterTheScheme(): void
    {
        self::assertSame('abc.def.ghi', $this->extract('Bearer    abc.def.ghi'));
    }

    public function testReturnsNullWhenTheHeaderIsAbsent(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/');

        self::assertNull((new BearerTokenExtractor('Authorization'))->extract($request));
    }

    public function testReturnsNullForANonBearerScheme(): void
    {
        // A Basic-auth header must never be fed to the JWT parser.
        self::assertNull($this->extract('Basic dXNlcjpwYXNz'));
    }

    public function testReturnsNullWhenTheSchemeCarriesNoToken(): void
    {
        self::assertNull($this->extract('Bearer'));
        self::assertNull($this->extract('Bearer   '));
    }

    private function extract(string $authorization): ?string
    {
        return (new BearerTokenExtractor('Authorization'))->extract($this->requestWith($authorization));
    }

    private function requestWith(string $authorization): ServerRequestInterface
    {
        return (new ServerRequestFactory())
            ->createServerRequest('GET', '/')
            ->withHeader('Authorization', $authorization);
    }
}
