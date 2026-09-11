<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http;

use Altair\Configuration\Support\Env;
use Laminas\Diactoros\Response\TextResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Tests\Support\RecordingOtpMailer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Univeros\Polaris\Http\PolarisMiddleware;
use Univeros\Polaris\Tests\Support\ArrayEnv;
use Univeros\Polaris\Tests\Support\TestPolaris;

use function json_decode;
use function json_encode;

final class PolarisMiddlewareTest extends TestCase
{
    private RecordingOtpMailer $mailer;
    private PolarisMiddleware $middleware;

    protected function setUp(): void
    {
        $this->mailer = new RecordingOtpMailer();
        $this->middleware = $this->boot();
    }

    public function testAManifestPathRunsThePolarisPipeline(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/auth/.well-known/jwks.json');

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame(200, $response->getStatusCode());
        self::assertArrayHasKey('keys', json_decode((string) $response->getBody(), true));
    }

    public function testAJsonBodyIsParsedFromTheBytesTheFrontControllerHandsOver(): void
    {
        // ServerRequestFactory::fromGlobals() hands $_POST over as the parsed body: an empty array.
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/auth/register')
            ->withHeader('Content-Type', 'application/json')
            ->withBody((new StreamFactory())->createStream(json_encode(['email' => 'ada@example.com', 'password' => 'Sup3r-Secret-Passw0rd'])))
            ->withParsedBody([]);

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame(202, $response->getStatusCode(), (string) $response->getBody());
        self::assertCount(1, $this->mailer->sent);
        self::assertSame('ada@example.com', $this->mailer->sent[0]['to']);
    }

    public function testAnotherPathContinuesToTheFrameworksDispatcher(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/ping');

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame('framework', (string) $response->getBody());
    }

    public function testAWrongMethodOnAPolarisPathAnswersPolaris405(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('DELETE', '/auth/.well-known/jwks.json');

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame(405, $response->getStatusCode());
        self::assertSame('GET', $response->getHeaderLine('Allow'));
    }

    public function testThePathPrefixMountsThePolarisRoutesUnderIt(): void
    {
        $middleware = $this->boot(new ArrayEnv(['POLARIS_PATH_PREFIX' => '/api']));

        $mounted = $middleware->process((new ServerRequestFactory())->createServerRequest('GET', '/api/auth/.well-known/jwks.json'), $this->handler());
        $bare = $middleware->process((new ServerRequestFactory())->createServerRequest('GET', '/auth/.well-known/jwks.json'), $this->handler());

        self::assertSame(200, $mounted->getStatusCode());
        self::assertSame('framework', (string) $bare->getBody());
    }

    private function boot(?Env $env = null): PolarisMiddleware
    {
        $instances = [OtpMailerInterface::class => $this->mailer];
        if ($env !== null) {
            $instances[Env::class] = $env;
        }
        $middleware = TestPolaris::boot($instances)->get(PolarisMiddleware::class);
        \assert($middleware instanceof PolarisMiddleware);

        return $middleware;
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new TextResponse('framework');
            }
        };
    }
}
