<?php

declare(strict_types=1);

namespace App;

use Altair\Container\Container;
use Altair\Http\Middleware\TokenAuthenticationMiddleware;
use Altair\Http\Rule\RequestPathRule;
use Altair\Http\Support\MiddlewarePriority;
use Altair\Module\Contracts\MiddlewareProviderInterface;
use Altair\Module\Contracts\ModuleInterface;
use App\Http\Middleware\AppAuthentication;
use App\Mail\FileMailer;
use Override;
use Polaris\Contract\OtpMailerInterface;

/**
 * What this application adds around Polaris: the demo mailbox (`var/mail.log`) as the mailer
 * Polaris sends through, and the framework's token authentication over Polaris access tokens on
 * the application's own `/app/*` routes, exactly the 1.x shape (a `RequestPathRule` at
 * `DISPATCHER + 5`).
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
        $container->singleton(
            AppAuthentication::class,
            static fn(Container $c): AppAuthentication => new AppAuthentication(
                $c->make(TokenAuthenticationMiddleware::class, ['rules' => [new RequestPathRule(['path' => ['/app']])]]),
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
