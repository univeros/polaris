<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use DateTimeImmutable;
use Override;
use Polaris\Authorization\Gate;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\BearerResolverProvider;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Http\Attributes;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Token\Token;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * A plugin credential the way polaris/api-keys has one: `Bearer fx_good` authenticates as user-9 with
 * the delegated permission `invoices.read`, `Bearer fx_revoked` is refused, anything else is not its.
 * Its middleware stamps `X-Credential-Layer` on what it wraps, as api-keys' applies a key's rate limit.
 */
final class CredentialPlugin extends AbstractPlugin implements BearerResolverProvider
{
    public const string GOOD = 'fx_good';
    public const string REVOKED = 'fx_revoked';
    public const string LAYER = 'X-Credential-Layer';

    #[Override]
    public function id(): string
    {
        return 'credential';
    }

    #[Override]
    public function bearerResolvers(Graph $graph): array
    {
        return [
            new class implements BearerResolver {
                public function resolve(ServerRequestInterface $request): ?TokenInterface
                {
                    $credential = substr($request->getHeaderLine('Authorization'), 7);

                    return match ($credential) {
                        CredentialPlugin::GOOD => new Token($credential, [
                            'sub' => 'user-9',
                            'jti' => 'fx-1',
                            'iat' => new DateTimeImmutable(),
                            Gate::DELEGATED => ['invoices.read'],
                        ]),
                        CredentialPlugin::REVOKED => throw new AuthorizationTokenException('The credential is revoked.'),
                        default => null,
                    };
                }
            },
        ];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [
            new class implements MiddlewareInterface {
                public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
                {
                    $token = $request->getAttribute(Attributes::TOKEN);

                    return $handler->handle($request)->withHeader(CredentialPlugin::LAYER, $token instanceof TokenInterface ? (string) $token->getMetadata('sub') : 'none');
                }
            },
        ];
    }
}
