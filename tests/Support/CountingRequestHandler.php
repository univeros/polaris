<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Laminas\Diactoros\ResponseFactory;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * A PSR-15 inner handler for middleware tests: returns a `200` and records how many times it was
 * reached, so a test can assert that a short-circuiting middleware (e.g. a `429`) never delegated.
 */
final class CountingRequestHandler implements RequestHandlerInterface
{
    public int $calls = 0;

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        ++$this->calls;

        return (new ResponseFactory())->createResponse(200);
    }
}
