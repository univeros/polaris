<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Univeros\Polaris\Tests\Support\TestKeys;

use function array_column;
use function putenv;

/**
 * Smoke test for the functional harness itself, driven through the already-shipped JWKS
 * endpoint: it proves a module route reaches its domain and a real JSON response comes back.
 */
final class JwksEndpointTest extends FunctionalTestCase
{
    public function testServesTheJwkSetOverHttp(): void
    {
        $response = $this->get('/auth/.well-known/jwks.json');

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('application/json', $response->getHeaderLine('Content-Type'));

        $body = $this->json($response);
        self::assertArrayHasKey('keys', $body);
        self::assertIsArray($body['keys']);
        self::assertSame('RSA', $body['keys'][0]['kty']);
    }

    public function testRotationOverlapPublishesBothKeys(): void
    {
        // Reboot the harness with a retiring previous key configured (docs/auth/key-rotation.md).
        $previous = TestKeys::rsa();
        putenv('AUTH_JWT_PREVIOUS_PUBLIC_KEY=' . $previous['public']);
        putenv('AUTH_JWT_PREVIOUS_KID=retiring-key');
        $this->setUp();

        $body = $this->json($this->get('/auth/.well-known/jwks.json'));
        $kids = array_column($body['keys'] ?? [], 'kid');

        self::assertCount(2, $kids);
        self::assertContains('retiring-key', $kids);
    }

    public function testUnknownRouteIsNotFound(): void
    {
        self::assertSame(404, $this->get('/auth/does-not-exist')->getStatusCode());
    }
}
