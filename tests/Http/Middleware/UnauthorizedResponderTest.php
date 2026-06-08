<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Middleware;

use Altair\Http\Exception\AuthorizationException;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Univeros\Polaris\Http\Middleware\UnauthorizedResponder;
use PHPUnit\Framework\TestCase;

use function json_decode;

final class UnauthorizedResponderTest extends TestCase
{
    public function testRewritesAnyAuthFailureToA401JsonEnvelope(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/auth/me');
        // The framework hands a 403 for a *missing* token; the responder normalises it to 401.
        $incoming = (new ResponseFactory())->createResponse(403);

        $response = (new UnauthorizedResponder())(
            $request,
            $incoming,
            new AuthorizationException('No authentication token has been specified.'),
        );

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));

        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('unauthorized', $body['error']);
        self::assertSame('Authentication is required.', $body['message']);
    }

    public function testWorksWithoutAnException(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/auth/me');
        $response = (new UnauthorizedResponder())($request, (new ResponseFactory())->createResponse(401), null);

        self::assertSame(401, $response->getStatusCode());
    }
}
