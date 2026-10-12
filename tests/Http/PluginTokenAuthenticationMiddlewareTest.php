<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http;

use Altair\Container\Container;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Rule\RequestPathRule;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\ApiKeys\Keys;
use Polaris\ApiKeys\Model\ApiKey;
use Polaris\Audit\AuditPlugin;
use Polaris\Authorization\Gate;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Token\ClientContext;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Http\PluginTokenAuthenticationMiddleware;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\CredentialPlugin;
use Univeros\Polaris\Tests\Support\RecordingHandler;
use Univeros\Polaris\Tests\Support\TestPolaris;
use Univeros\Polaris\Token\DualToken;

use function is_array;
use function is_string;
use function json_decode;

final class PluginTokenAuthenticationMiddlewareTest extends TestCase
{
    private Container $container;

    protected function setUp(): void
    {
        $this->container = TestPolaris::boot([Plugins::class => new Plugins(new CredentialPlugin())]);
    }

    public function testAPluginCredentialAuthenticatesAHostRouteAsADelegatedDualToken(): void
    {
        $handler = new RecordingHandler();

        $response = $this->middleware()->process(self::request('Bearer ' . CredentialPlugin::GOOD), $handler);

        self::assertSame(200, $response->getStatusCode());
        $seen = $handler->token();
        self::assertInstanceOf(DualToken::class, $seen);
        self::assertSame('user-9', $seen->getMetadata('sub'));
        self::assertSame(['invoices.read'], $seen->getMetadata(Gate::DELEGATED));
        self::assertSame('user-9', $response->getHeaderLine(CredentialPlugin::LAYER), 'the resolving plugin\'s middleware (a key\'s rate limit) wraps the route');
    }

    public function testARefusedPluginCredentialAnswersTheUnauthorizedEnvelope(): void
    {
        $handler = new RecordingHandler();

        $response = $this->middleware()->process(self::request('Bearer ' . CredentialPlugin::REVOKED), $handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('unauthorized', json_decode((string) $response->getBody(), true)['error']);
        self::assertNull($handler->request);
    }

    public function testACoreAccessTokenStillAuthenticates(): void
    {
        $handler = new RecordingHandler();
        $jwt = TestPolaris::accessToken(TestPolaris::graph($this->container), 'user-7');

        $response = $this->middleware()->process(self::request('Bearer ' . $jwt), $handler);

        self::assertSame(200, $response->getStatusCode());
        $seen = $handler->token();
        self::assertInstanceOf(DualToken::class, $seen);
        self::assertSame('user-7', $seen->getMetadata('sub'));
        self::assertFalse($response->hasHeader(CredentialPlugin::LAYER));
    }

    public function testWithoutACredentialItAnswers401(): void
    {
        $handler = new RecordingHandler();

        self::assertSame(401, $this->middleware()->process(self::request(null), $handler)->getStatusCode());
    }

    public function testTheHostsRulesScopeIt(): void
    {
        $handler = new RecordingHandler();
        $scoped = $this->container->make(PluginTokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]]);

        $response = $scoped->process((new ServerRequestFactory())->createServerRequest('GET', 'http://api.example.com/ping'), $handler);

        self::assertSame(200, $response->getStatusCode());
    }

    public function testTheFrameworksMiddlewareKeepsAcceptingPolarisSessionsOnly(): void
    {
        $handler = new RecordingHandler();
        $framework = $this->container->get(TokenAuthenticationMiddleware::class);
        \assert($framework instanceof TokenAuthenticationMiddleware);

        self::assertSame(401, $framework->process(self::request('Bearer ' . CredentialPlugin::GOOD), $handler)->getStatusCode());
    }

    public function testTheGateIsBoundForHostsThatAuthorizeDelegatedTokens(): void
    {
        self::assertSame(TestPolaris::graph($this->container)->gate(), $this->container->get(Gate::class));
    }

    public function testARealApiKeyIsHeldToItsOwnRateLimitOnTheHostsRoutes(): void
    {
        $database = new InMemoryAdapter();
        $container = TestPolaris::boot([DatabaseAdapter::class => $database, Plugins::class => new Plugins(new AuditPlugin(), new ApiKeysPlugin())]);
        $graph = TestPolaris::graph($container);
        $graph->registration()->register('ada@example.com', 'Sup3r-Secret-Passw0rd', null, ClientContext::none());
        $user = $database->findOne('auth_users', ['email' => 'ada@example.com']);
        \assert(is_array($user) && is_string($user['id']));
        $issued = $graph->get(Keys::class)->create(ApiKey::OWNER_USER, $user['id'], null, $user['id'], 'ci', [], [], rateLimit: ['window' => 60, 'max' => 1]);
        $middleware = $container->get(PluginTokenAuthenticationMiddleware::class);
        \assert($middleware instanceof PluginTokenAuthenticationMiddleware);

        $first = $middleware->process(self::request('Bearer ' . $issued->secret), new RecordingHandler());
        $second = $middleware->process(self::request('Bearer ' . $issued->secret), new RecordingHandler());

        self::assertSame(200, $first->getStatusCode());
        self::assertSame('1', $first->getHeaderLine('X-RateLimit-Limit'));
        self::assertSame(429, $second->getStatusCode());
    }

    private function middleware(): PluginTokenAuthenticationMiddleware
    {
        $middleware = $this->container->get(PluginTokenAuthenticationMiddleware::class);
        \assert($middleware instanceof PluginTokenAuthenticationMiddleware);

        return $middleware;
    }

    private static function request(?string $authorization): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', 'http://api.example.com/app/invoices');

        return $authorization === null ? $request : $request->withHeader('Authorization', $authorization);
    }
}
