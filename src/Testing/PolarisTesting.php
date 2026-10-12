<?php

declare(strict_types=1);

namespace Univeros\Polaris\Testing;

use Altair\Container\Container;
use Polaris\Authorization\Gate;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Token\AccessTokenClaims;
use Polaris\Wiring\Graph;
use RuntimeException;

use function bin2hex;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function random_bytes;

use const OPENSSL_KEYTYPE_RSA;

/**
 * For the host application's tests (`composer require --dev polaris/testing`): `bind()` gives the
 * container an in-memory database, a fresh RS256 key pair, an APP_KEY and an issuer before the module
 * applies, so the Polaris routes and the token middleware work without a database or a `.env`; `token()`
 * mints an access token to call a protected route as a user. What the container already binds wins.
 */
final class PolarisTesting
{
    public const string ISSUER = 'https://polaris.test';

    /** @var array{private: string, public: string}|null generated once per process: RSA generation is slow */
    private static ?array $keys = null;

    public static function bind(Container $container): void
    {
        $defaults = [
            DatabaseAdapter::class => static fn(): InMemoryAdapter => new InMemoryAdapter(),
            Secrets::class => static fn(): Secrets => Secrets::fromEnvironment([
                'APP_KEY' => bin2hex(random_bytes(32)),
                'AUTH_JWT_PRIVATE_KEY' => self::keys()['private'],
                'AUTH_JWT_PUBLIC_KEY' => self::keys()['public'],
            ]),
            AuthConfig::class => static fn(): AuthConfig => AuthConfig::fromArray(['issuer' => self::ISSUER]),
        ];
        foreach ($defaults as $id => $factory) {
            if (!$container->has($id)) {
                $container->instance($id, $factory());
            }
        }
    }

    /**
     * A signed Polaris access token for `Authorization: Bearer`. `delegated` limits it to a subset of the
     * user's permissions, as an API key or an OAuth token is (`Gate::DELEGATED`).
     *
     * @param list<string> $roles
     * @param list<string> $delegated
     */
    public static function token(
        Container $container,
        string $userId,
        ?string $organizationId = null,
        array $roles = [],
        bool $mfa = false,
        array $delegated = [],
    ): string {
        $graph = $container->get(Graph::class);
        \assert($graph instanceof Graph);
        $claims = new AccessTokenClaims(
            subject: $userId,
            jwtId: bin2hex(random_bytes(8)),
            organizationId: $organizationId,
            roles: $roles,
            emailVerified: true,
            mfa: $mfa,
            amr: $mfa ? ['pwd', 'otp'] : ['pwd'],
            extra: $delegated === [] ? [] : [Gate::DELEGATED => $delegated],
        );

        return $graph->tokenGenerator()->generate($claims->toClaims());
    }

    /**
     * @return array{private: string, public: string}
     */
    private static function keys(): array
    {
        if (self::$keys === null) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            $details = $key === false ? false : openssl_pkey_get_details($key);
            if ($key === false || $details === false || !openssl_pkey_export($key, $private)) {
                throw new RuntimeException('Cannot generate the RS256 test key pair: is ext-openssl configured?');
            }
            self::$keys = ['private' => (string) $private, 'public' => (string) $details['key']];
        }

        return self::$keys;
    }
}
