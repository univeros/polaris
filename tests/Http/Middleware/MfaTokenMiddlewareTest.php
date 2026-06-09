<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Contracts\TokenParserInterface;
use Altair\Http\Exception\InvalidTokenException;
use Altair\Http\Rule\RequestPathRule;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Http\Middleware\BearerTokenExtractor;
use Univeros\Polaris\Http\Middleware\MfaTicket;
use Univeros\Polaris\Http\Middleware\MfaTokenMiddleware;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Tests\Support\CountingRequestHandler;

use function preg_quote;

final class MfaTokenMiddlewareTest extends TestCase
{
    private CountingRequestHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new CountingRequestHandler();
    }

    public function testARequestOutsideTheGatePassesThroughUntouched(): void
    {
        $middleware = $this->middleware($this->tickets(subject: 'user-1'));

        $response = $middleware->process($this->request('/auth/me'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(1, $this->handler->calls);
    }

    public function testAValidTicketAttachesTheUserIdAndDelegates(): void
    {
        $handler = new class implements RequestHandlerInterface {
            public mixed $ticket = 'unset';
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                ++$this->calls;
                $this->ticket = $request->getAttribute(MfaTicket::ATTRIBUTE);

                return (new ResponseFactory())->createResponse(200);
            }
        };

        $response = $this->middleware($this->tickets(subject: 'user-1'))
            ->process($this->gateRequest('Bearer good-ticket'), $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertInstanceOf(MfaTicket::class, $handler->ticket);
        self::assertSame('user-1', $handler->ticket->userId);
        self::assertSame(1, $handler->calls);
    }

    public function testAMissingBearerIsRejected(): void
    {
        $response = $this->middleware($this->tickets(subject: 'user-1'))
            ->process($this->request('/auth/mfa/verify'), $this->handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(0, $this->handler->calls, 'the gate domain is never reached');
    }

    public function testAnInvalidTicketIsRejected(): void
    {
        $response = $this->middleware($this->tickets(throw: true))
            ->process($this->gateRequest('Bearer bad-ticket'), $this->handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(0, $this->handler->calls);
    }

    private function middleware(MfaLoginTokenService $tickets): MfaTokenMiddleware
    {
        return new MfaTokenMiddleware(
            new RequestPathRule(['path' => [
                preg_quote('/auth/mfa/challenge', '@'),
                preg_quote('/auth/mfa/verify', '@'),
            ]]),
            new BearerTokenExtractor(),
            $tickets,
            new ResponseFactory(),
        );
    }

    private function tickets(string $subject = 'user-1', bool $throw = false): MfaLoginTokenService
    {
        $parser = $this->createStub(TokenParserInterface::class);

        if ($throw) {
            $parser->method('parse')->willThrowException(new InvalidTokenException('bad'));
        } else {
            $token = $this->createStub(TokenInterface::class);
            $token->method('getMetadata')->willReturnMap([
                ['purpose', MfaLoginTokenService::PURPOSE],
                ['sub', $subject],
            ]);
            $parser->method('parse')->willReturn($token);
        }

        return new MfaLoginTokenService($this->createStub(\Altair\Http\Contracts\TokenGeneratorInterface::class), $parser);
    }

    private function request(string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('POST', $path);
    }

    private function gateRequest(string $authorization): ServerRequestInterface
    {
        return $this->request('/auth/mfa/verify')->withHeader('Authorization', $authorization);
    }
}
