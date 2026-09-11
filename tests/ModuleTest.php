<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests;

use Altair\Container\Container;
use Altair\Http\Contracts\CredentialsExtractorInterface;
use Altair\Http\Contracts\IdentityValidatorInterface;
use Altair\Http\Contracts\TokenExtractorInterface;
use Altair\Http\Contracts\TokenFactoryInterface;
use Altair\Http\Contracts\TokenInterface;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Rule\RequestPathRule;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\MigrationDirectoriesProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use Laminas\Diactoros\Response\TextResponse;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Exception\InvalidConfigException;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Psr15\Router;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Http\BearerTokenExtractor;
use Univeros\Polaris\Http\NullCredentialsExtractor;
use Univeros\Polaris\Http\NullIdentityValidator;
use Univeros\Polaris\Http\PolarisMiddleware;
use Univeros\Polaris\Module;
use Univeros\Polaris\Tests\Support\TestPolaris;
use Univeros\Polaris\Token\DualToken;
use Univeros\Polaris\Token\TokenFactoryBridge;

use function dirname;
use function json_decode;

final class ModuleTest extends TestCase
{
    public function testIsAUniverosModuleContributingMiddlewareAndMigrations(): void
    {
        $module = new Module();

        self::assertInstanceOf(ModuleInterface::class, $module);
        self::assertInstanceOf(MiddlewareProviderInterface::class, $module);
        self::assertInstanceOf(MigrationDirectoriesProviderInterface::class, $module);
        self::assertSame('univeros/polaris', $module->name());
    }

    public function testThePolarisMiddlewareRunsAheadOfTheExceptionHandler(): void
    {
        self::assertSame(
            [['middleware' => PolarisMiddleware::class, 'priority' => MiddlewarePriority::EXCEPTION_HANDLER - 100]],
            (new Module())->middleware(),
        );
    }

    public function testShipsItsMigrationsDirectory(): void
    {
        [$source] = (new Module())->migrationDirectories();

        self::assertSame(dirname(__DIR__) . '/migrations', $source->directory);
        self::assertSame('Univeros\\Polaris\\Migrations', $source->namespace);
        self::assertDirectoryExists($source->directory);
    }

    public function testBindsOnePolarisAndItsHttpFace(): void
    {
        $container = TestPolaris::boot();

        $polaris = $container->get(Polaris::class);
        self::assertInstanceOf(Polaris::class, $polaris);
        self::assertSame($polaris, $container->get(Polaris::class));
        self::assertSame($polaris->graph(), $container->get(Graph::class));
        self::assertInstanceOf(Pipeline::class, $container->get(Pipeline::class));
        self::assertInstanceOf(Router::class, $container->get(Router::class));
        self::assertInstanceOf(PolarisMiddleware::class, $container->get(PolarisMiddleware::class));
    }

    public function testBindsTheFrameworkTokenContractsOverPolaris(): void
    {
        $container = TestPolaris::boot();

        self::assertInstanceOf(TokenFactoryBridge::class, $container->get(TokenFactoryInterface::class));
        self::assertInstanceOf(BearerTokenExtractor::class, $container->get(TokenExtractorInterface::class));
        self::assertInstanceOf(NullCredentialsExtractor::class, $container->get(CredentialsExtractorInterface::class));
        self::assertInstanceOf(NullIdentityValidator::class, $container->get(IdentityValidatorInterface::class));
        self::assertInstanceOf(ResponseFactory::class, $container->get(ResponseFactoryInterface::class));
    }

    public function testAHostBoundResponseFactoryAndIdentityValidatorAreKept(): void
    {
        $responses = new ResponseFactory();
        $validator = new NullIdentityValidator();
        $container = TestPolaris::boot([ResponseFactoryInterface::class => $responses, IdentityValidatorInterface::class => $validator]);

        self::assertSame($responses, $container->get(ResponseFactoryInterface::class));
        self::assertSame($validator, $container->get(IdentityValidatorInterface::class));
    }

    public function testTheTokenAuthenticationMiddlewareAnswers401OverPlainHttpWithTheEnvelope(): void
    {
        $container = TestPolaris::boot();
        $middleware = $container->get(TokenAuthenticationMiddleware::class);
        self::assertInstanceOf(TokenAuthenticationMiddleware::class, $middleware);

        // Behind TLS termination the scheme PHP sees is http and the host is not local: `ssl => false`.
        $response = $middleware->process($this->request('GET', 'http://api.example.com/app/me'), $this->handler());

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame(['error' => 'unauthorized', 'message' => 'Authentication is required.'], json_decode((string) $response->getBody(), true));
    }

    public function testTheTokenAuthenticationMiddlewareAttachesADualTokenForAPolarisAccessToken(): void
    {
        $container = TestPolaris::boot();
        $middleware = $container->get(TokenAuthenticationMiddleware::class);
        self::assertInstanceOf(TokenAuthenticationMiddleware::class, $middleware);
        $jwt = TestPolaris::accessToken(TestPolaris::graph($container), 'user-7');
        $seen = null;

        $response = $middleware->process(
            $this->request('GET', 'http://api.example.com/app/me')->withHeader('Authorization', 'Bearer ' . $jwt),
            $this->handler(function (ServerRequestInterface $request) use (&$seen): void {
                $seen = $request->getAttribute(TokenInterface::TOKEN_KEY);
            }),
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertInstanceOf(DualToken::class, $seen);
        self::assertSame('user-7', $seen->getMetadata('sub'));
        self::assertSame($jwt, $seen->getToken());
    }

    public function testTheHostScopesTheTokenAuthenticationMiddlewareWithItsOwnRules(): void
    {
        $container = TestPolaris::boot();

        $scoped = $container->make(TokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]]);

        self::assertSame(200, $scoped->process($this->request('GET', 'http://api.example.com/ping'), $this->handler())->getStatusCode());
        self::assertSame(401, $scoped->process($this->request('GET', 'http://api.example.com/app/me'), $this->handler())->getStatusCode());
    }

    public function testNothingIsBuiltBeforeTheFirstResolution(): void
    {
        $container = new Container();
        (new Module())->apply($container); // no database, no secrets: `db:migrate` boots like this

        self::assertTrue($container->has(Polaris::class));
        $this->expectException(InvalidConfigException::class);
        $container->get(Polaris::class);
    }

    private function request(string $method, string $uri): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest($method, $uri);
    }

    /**
     * @param (callable(ServerRequestInterface): void)|null $observer
     */
    private function handler(?callable $observer = null): RequestHandlerInterface
    {
        return new class ($observer) implements RequestHandlerInterface {
            /**
             * @param (callable(ServerRequestInterface): void)|null $observer
             */
            public function __construct(private $observer)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                if ($this->observer !== null) {
                    ($this->observer)($request);
                }

                return new TextResponse('ok');
            }
        };
    }
}
