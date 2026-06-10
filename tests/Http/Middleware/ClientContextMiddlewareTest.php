<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Http\Middleware\ClientContextMiddleware;

use function str_repeat;
use function strlen;

final class ClientContextMiddlewareTest extends TestCase
{
    public function testAttachesTheUserAgentAsARequestAttribute(): void
    {
        $seen = $this->process($this->request()->withHeader('User-Agent', 'Browser/1.0'));

        self::assertSame('Browser/1.0', $seen->getAttribute(ClientContextMiddleware::ATTRIBUTE_USER_AGENT));
    }

    public function testStripsControlCharactersAndTruncatesToTheColumnSize(): void
    {
        // A tab is a control character that survives PSR-7 header validation; CR/LF/NUL are
        // rejected by the message implementation itself before they ever reach the middleware.
        $hostile = "Evil/1.0\tInjected" . str_repeat('a', 300);

        $seen = $this->process($this->request()->withHeader('User-Agent', $hostile));

        $attribute = (string) $seen->getAttribute(ClientContextMiddleware::ATTRIBUTE_USER_AGENT);
        self::assertStringNotContainsString("\t", $attribute);
        self::assertSame(255, strlen($attribute), 'bounded to the user_agent column size');
        self::assertStringStartsWith('Evil/1.0Injected', $attribute);
    }

    public function testAnAbsentHeaderSetsNoAttribute(): void
    {
        $seen = $this->process($this->request());

        self::assertNull($seen->getAttribute(ClientContextMiddleware::ATTRIBUTE_USER_AGENT));
    }

    private function process(ServerRequestInterface $request): ServerRequestInterface
    {
        $handler = new class () implements RequestHandlerInterface {
            public ?ServerRequestInterface $request = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->request = $request;

                return new Response();
            }
        };

        (new ClientContextMiddleware())->process($request, $handler);
        self::assertNotNull($handler->request);

        return $handler->request;
    }

    private function request(): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('POST', '/auth/login');
    }
}
