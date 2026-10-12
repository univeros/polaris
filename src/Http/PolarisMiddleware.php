<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http;

use Override;
use Polaris\Psr15\Pipeline;
use Polaris\Psr15\Router;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_array;
use function json_decode;
use function preg_match;
use function preg_quote;
use function rtrim;
use function str_contains;
use function str_starts_with;

/**
 * Serves every Polaris path through the Polaris pipeline, ahead of the framework's exception
 * handler (which rewrites 4xx/5xx responses into problem+json) and outside the FastRoute table.
 * Any other path continues to the framework's dispatcher.
 */
final readonly class PolarisMiddleware implements MiddlewareInterface
{
    public function __construct(private Router $router, private Pipeline $pipeline, private string $pathPrefix = '/')
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $alias = $this->wellKnown($path);
        if ($alias !== null) {
            $request = $request->withUri($request->getUri()->withPath($alias));
            $path = $alias;
        }
        // The router also matches a path without the prefix; only the mounted paths are Polaris's.
        if (!$this->mounted($path)) {
            return $handler->handle($request);
        }
        $match = $this->router->match($request->getMethod(), $path);
        if ($match->spec === null && $match->allowedMethods === []) {
            return $handler->handle($request);
        }

        // A known path with the wrong method answers Polaris's 405.
        return $this->pipeline->handle(self::withJsonBody($request));
    }

    /**
     * RFC 8414 and RFC 9728 put `/.well-known/<name>` between the host and the issuer's or resource's
     * path, so under the prefix `/auth` a client asks `/.well-known/oauth-authorization-server/auth`
     * for what Polaris serves at `/auth/.well-known/oauth-authorization-server` (and
     * `/.well-known/oauth-protected-resource/auth/mcp` for `/auth/.well-known/oauth-protected-resource/mcp`).
     * The mounted path, when that is a Polaris route; null otherwise.
     */
    private function wellKnown(string $path): ?string
    {
        $prefix = rtrim($this->pathPrefix, '/');
        if ($prefix === '' || preg_match('#^/\.well-known/([^/]+)(' . preg_quote($prefix, '#') . ')(/.*)?$#', $path, $parts) !== 1) {
            return null;
        }
        $mounted = $prefix . '/.well-known/' . $parts[1] . ($parts[3] ?? '');
        $match = $this->router->match('GET', $mounted);

        return $match->spec !== null ? $mounted : null;
    }

    private function mounted(string $path): bool
    {
        $prefix = rtrim($this->pathPrefix, '/');

        return $prefix === '' || str_starts_with($path, $prefix . '/');
    }

    /**
     * `ServerRequestFactory::fromGlobals()` hands `$_POST` over as the parsed body: an empty array
     * for a JSON request, whose bytes are decoded here.
     */
    private static function withJsonBody(ServerRequestInterface $request): ServerRequestInterface
    {
        $parsed = $request->getParsedBody();
        if (($parsed !== null && $parsed !== []) || !str_contains($request->getHeaderLine('Content-Type'), 'json')) {
            return $request;
        }
        $decoded = json_decode((string) $request->getBody(), true);

        return is_array($decoded) ? $request->withParsedBody($decoded) : $request;
    }
}
