<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http;

use Altair\Http\Contracts\CredentialsExtractorInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Exception\AuthorizationTokenException as AltairAuthorizationTokenException;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Override;
use Polaris\Contract\BearerResolverProvider;
use Polaris\Contract\Plugin;
use Polaris\Contract\TokenInterface as PolarisToken;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Http\Attributes;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Token\DualToken;

use function array_reverse;
use function is_callable;

/**
 * The framework's token authentication, plus the plugins' credentials: an API key (`polaris/api-keys`)
 * or an OAuth access token (`polaris/oauth-provider`) authenticates the host's own routes the way it
 * authenticates the Polaris routes: the plugins' bearer resolvers asked with the real request, then
 * the resolving plugin's middleware around the route (a key's own rate limit).
 * Opt-in: mount it instead of `TokenAuthenticationMiddleware` on the paths that accept them. A
 * resolved token carries `Gate::DELEGATED` (the subset of its owner's permissions it may use); only
 * `Polaris\Authorization\Gate` applies that restriction, so authorize such requests through the Gate.
 */
final class PluginTokenAuthenticationMiddleware extends TokenAuthenticationMiddleware
{
    /**
     * @param list<\Altair\Http\Contracts\HttpAuthRuleInterface>|null $rules
     * @param array<string, mixed>|null $options
     */
    public function __construct(
        private readonly Graph $graph,
        private readonly ResponseFactoryInterface $responses,
        TokenExtractorInterface $tokenExtractor,
        CredentialsExtractorInterface $credentialsExtractor,
        TokenFactoryInterface $tokenFactory,
        IdentityValidatorInterface $identityValidator,
        ?array $rules = null,
        ?array $options = null,
    ) {
        parent::__construct($tokenExtractor, $credentialsExtractor, $tokenFactory, $identityValidator, $responses, $rules, $options);
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->shouldAuthenticateRequest($request)) {
            return $handler->handle($request);
        }
        $this->checkAllowance($request->getUri()->getHost(), $request->getUri()->getScheme());
        try {
            $resolved = $this->resolve($request);
        } catch (AuthorizationTokenException $exception) {
            return $this->unauthorized($request, new AltairAuthorizationTokenException($exception->getMessage(), $exception));
        }
        if ($resolved === null) {
            return parent::process($request, $handler);
        }
        [$plugin, $token] = $resolved;
        $request = $request->withAttribute(TokenInterface::TOKEN_KEY, new DualToken($token))->withAttribute(Attributes::TOKEN, $token);

        return self::through($plugin->middleware($this->graph), $handler)->handle($request);
    }

    /**
     * The first plugin resolver that recognises the request, in registration order, and its plugin.
     *
     * @return array{Plugin, PolarisToken}|null
     */
    private function resolve(ServerRequestInterface $request): ?array
    {
        foreach ($this->graph->plugins() as $plugin) {
            if (!$plugin instanceof BearerResolverProvider) {
                continue;
            }
            foreach ($plugin->bearerResolvers($this->graph) as $resolver) {
                $token = $resolver->resolve($request);
                if ($token !== null) {
                    return [$plugin, $token];
                }
            }
        }

        return null;
    }

    /**
     * The resolving plugin's middleware around the host's route, as the Polaris pipeline runs it
     * after the bearer parse: api-keys applies a key's own rate limit there.
     *
     * @param list<MiddlewareInterface> $middleware
     */
    private static function through(array $middleware, RequestHandlerInterface $handler): RequestHandlerInterface
    {
        foreach (array_reverse($middleware) as $layer) {
            $handler = new readonly class ($layer, $handler) implements RequestHandlerInterface {
                public function __construct(private MiddlewareInterface $layer, private RequestHandlerInterface $next)
                {
                }

                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    return $this->layer->process($request, $this->next);
                }
            };
        }

        return $handler;
    }

    private function unauthorized(ServerRequestInterface $request, AltairAuthorizationTokenException $exception): ResponseInterface
    {
        $response = $this->responses->createResponse(401);
        if (is_callable($this->onError)) {
            $answer = ($this->onError)($request, $response, $exception);
            if ($answer instanceof ResponseInterface) {
                return $answer;
            }
        }

        return $response;
    }
}
