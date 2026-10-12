<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http;

use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Capability;
use Polaris\Agents\Http\AgentRequestMiddleware;
use Polaris\Audit\AuditPlugin;
use Polaris\OAuth\OAuthPlugin;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\RecordingHandler;
use Univeros\Polaris\Tests\Support\TestPolaris;

final class AgentRequestMiddlewareTest extends TestCase
{
    public function testTheAgentsRequestMiddlewareGuardsTheCapabilityLocationsOfTheHostsRoutes(): void
    {
        $plugins = new Plugins(
            new AuditPlugin(),
            new AdminPlugin(),
            new OAuthPlugin(baseUrl: 'https://app.example.com'),
            new AgentsPlugin(baseUrl: 'https://app.example.com', capabilities: [
                new Capability('invite', 'Invite a member', ['type' => 'object', 'properties' => ['email' => ['type' => 'string']], 'required' => ['email']], 'members.invite', location: 'https://app.example.com/app/invite'),
            ]),
        );
        $container = TestPolaris::boot([Plugins::class => $plugins]);

        $middleware = $container->get(AgentRequestMiddleware::class);
        $handler = new RecordingHandler();
        $response = $middleware->process((new ServerRequestFactory())->createServerRequest('GET', 'https://app.example.com/app/me'), $handler);

        self::assertInstanceOf(AgentRequestMiddleware::class, $middleware);
        self::assertSame(200, $response->getStatusCode(), 'a URL that is no capability location passes through');
        self::assertNotNull($handler->request);

        $guarded = new RecordingHandler();
        $refused = $middleware->process((new ServerRequestFactory())->createServerRequest('POST', 'https://app.example.com/app/invite'), $guarded);
        self::assertSame(401, $refused->getStatusCode(), 'a capability location needs an agent');
        self::assertNull($guarded->request);
    }
}
