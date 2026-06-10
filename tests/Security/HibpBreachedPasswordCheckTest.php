<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Security;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\TextResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Univeros\Polaris\Security\HibpBreachedPasswordCheck;

use function sha1;
use function strtoupper;
use function substr;

/**
 * Verifies the #41 HIBP k-anonymity adapter: only the 5-character SHA-1 prefix is sent, a
 * matching suffix in the range response reads as breached, and any upstream failure (non-200,
 * exception) fails open as "not breached".
 */
final class HibpBreachedPasswordCheckTest extends TestCase
{
    private const string PASSWORD = 'password123';

    public function testAMatchingSuffixIsBreachedAndOnlyThePrefixLeavesTheProcess(): void
    {
        $hash = strtoupper(sha1(self::PASSWORD));
        $sent = null;
        $client = $this->client(static function (RequestInterface $request) use ($hash, &$sent): ResponseInterface {
            $sent = (string) $request->getUri();

            return new TextResponse("AAAAA1234567890AAAAA1234567890AAAAA:3\r\n" . substr($hash, 5) . ":42\r\nBBBBB:1");
        });

        $check = new HibpBreachedPasswordCheck($client, new RequestFactory(), new NullLogger());

        self::assertTrue($check->isBreached(self::PASSWORD));
        self::assertSame('https://api.pwnedpasswords.com/range/' . substr($hash, 0, 5), $sent);
    }

    public function testAnAbsentSuffixIsNotBreached(): void
    {
        $client = $this->client(static fn(): ResponseInterface => new TextResponse("AAAAA1234567890AAAAA1234567890AAAAA:3\r\nBBBBB:1"));

        $check = new HibpBreachedPasswordCheck($client, new RequestFactory(), new NullLogger());

        self::assertFalse($check->isBreached(self::PASSWORD));
    }

    public function testANon200ResponseFailsOpen(): void
    {
        $client = $this->client(static fn(): ResponseInterface => new TextResponse('slow down', 429));

        $check = new HibpBreachedPasswordCheck($client, new RequestFactory(), new NullLogger());

        self::assertFalse($check->isBreached(self::PASSWORD));
    }

    public function testATransportErrorFailsOpen(): void
    {
        $client = $this->client(static function (): ResponseInterface {
            throw new RuntimeException('connection refused');
        });

        $check = new HibpBreachedPasswordCheck($client, new RequestFactory(), new NullLogger());

        self::assertFalse($check->isBreached(self::PASSWORD));
    }

    /**
     * @param callable(RequestInterface): ResponseInterface $handler
     */
    private function client(callable $handler): ClientInterface
    {
        return new class ($handler) implements ClientInterface {
            /**
             * @param callable(RequestInterface): ResponseInterface $handler
             */
            public function __construct(private $handler)
            {
            }

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return ($this->handler)($request);
            }
        };
    }
}
