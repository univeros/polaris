<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

use Altair\Http\Contracts\MiddlewareInterface;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function mb_substr;
use function preg_replace;

/**
 * Attaches the client's sanitized `User-Agent` as a request attribute, so the domains can carry
 * it into {@see \Univeros\Polaris\Token\ClientContext} for session rows and audit events
 * (issue #90).
 *
 * The header is attacker-controlled input headed for the database and for log/SIEM consumers,
 * so it is bounded and cleaned here — once, at the edge — rather than trusted downstream:
 * control characters are stripped (a crafted UA must not inject newlines into log pipelines)
 * and the value is truncated to the 255-character column size of `auth_refresh_tokens` and
 * `auth_audit_log` (a multi-kilobyte UA would otherwise fail or silently truncate
 * driver-dependently). An absent or blank header sets no attribute.
 */
final readonly class ClientContextMiddleware implements MiddlewareInterface
{
    public const string ATTRIBUTE_USER_AGENT = 'polaris:http:user-agent';

    /** The size of the `user_agent` columns this value is stored in. */
    private const int MAX_LENGTH = 255;

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $userAgent = $this->sanitize($request->getHeaderLine('User-Agent'));
        if ($userAgent !== '') {
            $request = $request->withAttribute(self::ATTRIBUTE_USER_AGENT, $userAgent);
        }

        return $handler->handle($request);
    }

    private function sanitize(string $userAgent): string
    {
        $clean = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $userAgent);

        return mb_substr($clean, 0, self::MAX_LENGTH);
    }
}
