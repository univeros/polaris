<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * A plugin with no routes or tables: one permission and one middleware stamping `X-Header-Plugin` on
 * every Polaris response, so a test sees that the module hands its plugins to Polaris.
 */
final class HeaderPlugin extends AbstractPlugin
{
    public const string HEADER = 'X-Header-Plugin';
    public const string PERMISSION = 'header.read';

    #[Override]
    public function id(): string
    {
        return 'header';
    }

    #[Override]
    public function permissions(): array
    {
        return [self::PERMISSION => 'Read the header fixture'];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [
            new class implements MiddlewareInterface {
                public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
                {
                    return $handler->handle($request)->withHeader(HeaderPlugin::HEADER, 'on');
                }
            },
        ];
    }
}
