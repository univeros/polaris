<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Http\Contracts\TokenInterface;
use Laminas\Diactoros\Response\TextResponse;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The host's route behind an authentication middleware: answers `ok` and keeps the request it got,
 * so a test reads the token the middleware attached.
 */
final class RecordingHandler implements RequestHandlerInterface
{
    public ?ServerRequestInterface $request = null;

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->request = $request;

        return new TextResponse('ok');
    }

    public function token(): mixed
    {
        return $this->request?->getAttribute(TokenInterface::TOKEN_KEY);
    }
}
