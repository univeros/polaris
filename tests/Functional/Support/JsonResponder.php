<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional\Support;

use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\ResponderInterface;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Minimal JSON responder for the functional harness: serialises a domain {@see PayloadInterface}
 * to a JSON body with its status. Polaris ships no responder of its own (the host provides
 * content negotiation); this stands in so functional tests exercise the real Action →
 * Domain → Payload path and assert on a concrete HTTP response.
 */
final class JsonResponder implements ResponderInterface
{
    #[Override]
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        PayloadInterface $payload,
    ): ResponseInterface {
        $response = $response
            ->withStatus($payload->getStatus() ?? 200)
            ->withHeader('Content-Type', 'application/json');

        $output = $payload->getOutput();
        if ($output !== []) {
            $response->getBody()->write(json_encode($output, JSON_THROW_ON_ERROR));
        }

        return $response;
    }
}
