<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Rule;

use Altair\Http\Rule\RequestPathRule;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Http\Rule\AnyRule;
use Univeros\Polaris\Http\Rule\MethodPathRule;

final class RulesTest extends TestCase
{
    public function testMethodPathRuleMatchesOnlyTheGivenMethod(): void
    {
        $rule = new MethodPathRule('DELETE', new RequestPathRule(['path' => ['/auth/mfa/factors']]));

        self::assertTrue($rule($this->request('DELETE', '/auth/mfa/factors/abc')));
        self::assertFalse($rule($this->request('GET', '/auth/mfa/factors')), 'GET on the same path is not matched');
        self::assertFalse($rule($this->request('DELETE', '/auth/me')), 'a different path is not matched');
    }

    public function testAnyRuleMatchesWhenAnyChildMatches(): void
    {
        $rule = new AnyRule(
            new RequestPathRule(['path' => ['/auth/password/change']]),
            new MethodPathRule('DELETE', new RequestPathRule(['path' => ['/auth/mfa/factors']])),
        );

        self::assertTrue($rule($this->request('POST', '/auth/password/change')));
        self::assertTrue($rule($this->request('DELETE', '/auth/mfa/factors/abc')));
        self::assertFalse($rule($this->request('GET', '/auth/mfa/factors')));
        self::assertFalse($rule($this->request('GET', '/auth/me')));
    }

    public function testAnEmptyAnyRuleMatchesNothing(): void
    {
        self::assertFalse((new AnyRule())($this->request('GET', '/auth/me')));
    }

    private function request(string $method, string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest($method, $path);
    }
}
