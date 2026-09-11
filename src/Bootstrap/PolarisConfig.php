<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Polaris\Config\AuthConfig;
use Polaris\Config\EnvironmentConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\MetricsInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RateStore;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Wiring\Config;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Univeros\Polaris\Database\Connection;
use Univeros\Polaris\Event\ListenerDispatcher;

use function is_string;

/**
 * The Polaris {@see Config} of a Univeros host. Every port takes what the container binds, else
 * core's default. The secrets and auth settings are the bound {@see Secrets} and {@see AuthConfig}
 * or the environment 1.x read (`APP_KEY`, `AUTH_JWT_*`, `AUTH_ISSUER`, `AUTH_AUDIENCE`,
 * `AUTH_ACCESS_TOKEN_DENYLIST`, `AUTH_PASSWORD_BREACH_CHECK`). The database is a bound
 * {@see DatabaseAdapter} or `PDO`, else a connection opened beside Cycle's from the framework's
 * {@see DatabaseSettings} or `POLARIS_DSN` ({@see Connection}). Without a bound PSR-14 dispatcher
 * the module dispatches to `Polaris::listeners()` itself (the audit log, notifications, metrics).
 */
final class PolarisConfig
{
    private const array AUTH_KEYS = ['AUTH_ISSUER', 'AUTH_AUDIENCE', 'AUTH_ACCESS_TOKEN_DENYLIST', 'AUTH_PASSWORD_BREACH_CHECK'];

    public static function fromContainer(Container $container, Env $env): Config
    {
        return new Config(
            secrets: self::secrets($container, $env),
            auth: self::auth($container, $env),
            database: self::database($container, $env),
            mailer: self::port($container, OtpMailerInterface::class),
            sms: self::port($container, SmsSenderInterface::class),
            breachCheck: self::port($container, BreachedPasswordCheckInterface::class),
            cache: self::port($container, CacheInterface::class),
            clock: self::port($container, ClockInterface::class),
            dispatcher: self::port($container, EventDispatcherInterface::class) ?? self::dispatcher($container),
            logger: self::port($container, LoggerInterface::class),
            rateLimits: self::port($container, RateLimitConfig::class),
            rateStore: self::port($container, RateStore::class),
            encrypter: self::port($container, EncrypterInterface::class),
            metrics: self::port($container, MetricsInterface::class),
            totp: self::port($container, TotpProviderInterface::class),
            qrCodes: self::port($container, QrCodeRendererInterface::class),
            responseFactory: self::port($container, ResponseFactoryInterface::class),
            pathPrefix: self::pathPrefix($env),
        );
    }

    /**
     * The bound {@see Secrets}, else `APP_KEY` and `AUTH_JWT_*` from the environment.
     */
    public static function secrets(Container $container, Env $env): Secrets
    {
        return self::port($container, Secrets::class) ?? EnvironmentConfig::secrets(self::environment($env));
    }

    /**
     * The bound {@see AuthConfig}, else `AUTH_ISSUER`, `AUTH_AUDIENCE`, `AUTH_ACCESS_TOKEN_DENYLIST` and
     * `AUTH_PASSWORD_BREACH_CHECK` from the environment over core's defaults.
     */
    public static function auth(Container $container, Env $env): AuthConfig
    {
        return self::port($container, AuthConfig::class) ?? EnvironmentConfig::auth(self::environment($env));
    }

    /**
     * `POLARIS_PATH_PREFIX`, the path the Polaris routes are mounted under; `/` by default.
     */
    public static function pathPrefix(Env $env): string
    {
        $prefix = $env->get('POLARIS_PATH_PREFIX');

        return is_string($prefix) && $prefix !== '' ? $prefix : '/';
    }

    private static function database(Container $container, Env $env): DatabaseAdapter
    {
        return self::port($container, DatabaseAdapter::class) ?? new PdoAdapter(Connection::fromContainer($container, $env));
    }

    private static function dispatcher(Container $container): ListenerDispatcher
    {
        return new ListenerDispatcher(static function () use ($container): array {
            $polaris = $container->get(Polaris::class);
            \assert($polaris instanceof Polaris);

            return $polaris->listeners();
        });
    }

    /**
     * The variables Polaris reads, through the framework's {@see Env} (`$_ENV`, `$_SERVER`, then
     * `getenv()`), so a `.env` loaded by the framework is seen the way the framework sees it.
     *
     * @return array<string, string>
     */
    private static function environment(Env $env): array
    {
        $values = [];
        foreach ([...EnvironmentConfig::SECRET_KEYS, ...self::AUTH_KEYS] as $key) {
            $value = $env->get($key);
            if (is_string($value)) {
                $values[$key] = $value;
            }
        }

        return $values;
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T|null
     */
    private static function port(Container $container, string $class): ?object
    {
        if (!$container->has($class)) {
            return null;
        }
        $service = $container->get($class);

        return $service instanceof $class ? $service : null;
    }
}
