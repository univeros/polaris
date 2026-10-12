<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Polaris\Cli\CommandProvider;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * A plugin with no routes or tables: one permission and one middleware stamping `X-Header-Plugin` on
 * every Polaris response, and one console command (`header:ping`), so a test sees that the module
 * hands its plugins to Polaris and their commands to `bin/altair`.
 */
final class HeaderPlugin extends AbstractPlugin implements CommandProvider
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

    #[Override]
    public function commands(Graph $graph): array
    {
        return [
            new class ($graph) extends Command {
                public function __construct(private readonly Graph $graph)
                {
                    parent::__construct('header:ping');
                }

                protected function execute(InputInterface $input, OutputInterface $output): int
                {
                    $output->writeln('pong from ' . $this->graph->plugin('header')->id());

                    return Command::SUCCESS;
                }
            },
        ];
    }
}
