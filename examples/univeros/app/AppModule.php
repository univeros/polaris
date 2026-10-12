<?php

declare(strict_types=1);

namespace App;

use Altair\Container\Container;
use Altair\Http\Rule\RequestPathRule;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use App\Http\Middleware\AppAuthentication;
use App\Mail\FileMailer;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Mcp\McpPlugin;
use Polaris\OAuth\OAuthPlugin;
use Univeros\Polaris\Http\PluginTokenAuthenticationMiddleware;
use Univeros\Polaris\Plugins;

/**
 * What this application adds around Polaris: the demo mailbox (`var/mail.log`) as the mailer
 * Polaris sends through, five plugins (audit, admin, API keys, the OAuth provider, MCP), and token
 * authentication on the application's own `/app/*` routes (a `RequestPathRule` at `DISPATCHER + 5`)
 * that accepts Polaris sessions, API keys and OAuth access tokens.
 */
final class AppModule implements ModuleInterface, MiddlewareProviderInterface
{
    public function __construct(private readonly string $root)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'app';
    }

    #[Override]
    public function apply(Container $container): void
    {
        $container->instance(OtpMailerInterface::class, new FileMailer($this->root . '/var/mail.log'));
        // The plugins this demo runs: the OAuth provider and the MCP server need the URL Polaris is
        // mounted at (the demo serves it at the root).
        $base = getenv('APP_URL') ?: 'http://127.0.0.1:8080';
        $container->instance(Plugins::class, new Plugins(
            new AuditPlugin(),
            new AdminPlugin(),
            new ApiKeysPlugin(),
            new OAuthPlugin(baseUrl: $base, audiences: [$base . '/mcp']),
            new McpPlugin($base, new ServerRequestFactory(), new ResponseFactory(), new StreamFactory()),
        ));
        // `/app/*` accepts Polaris sessions and, through the plugins' resolvers, API keys and OAuth tokens.
        $container->singleton(
            AppAuthentication::class,
            static fn(Container $c): AppAuthentication => new AppAuthentication(
                $c->make(PluginTokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]]),
            ),
        );
    }

    /**
     * @return list<array{middleware: class-string<AppAuthentication>, priority: int}>
     */
    #[Override]
    public function middleware(): array
    {
        return [['middleware' => AppAuthentication::class, 'priority' => MiddlewarePriority::DISPATCHER + 5]];
    }
}
