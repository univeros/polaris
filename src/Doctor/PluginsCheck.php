<?php

declare(strict_types=1);

namespace Univeros\Polaris\Doctor;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Doctor\Contracts\CheckInterface;
use Altair\Doctor\Result\CheckResult;
use Override;
use Polaris\Contract\Plugin;
use Throwable;
use Univeros\Polaris\Bootstrap\PolarisConfig;

use function array_map;
use function count;
use function implode;
use function is_object;
use function is_string;
use function method_exists;
use function parse_url;
use function property_exists;
use function rtrim;
use function sprintf;

use const PHP_URL_PATH;

/**
 * `polaris_plugins` in `bin/altair doctor`: the configured plugins build, and every plugin taking a
 * `baseUrl` is mounted where `POLARIS_PATH_PREFIX` mounts Polaris (MCP dispatches its tools to that
 * path; the callbacks and links the others hand out derive from it).
 */
final readonly class PluginsCheck implements CheckInterface
{
    public function __construct(private Container $container, private Env $env)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'polaris_plugins';
    }

    #[Override]
    public function dependsOn(): array
    {
        return [];
    }

    #[Override]
    public function run(): CheckResult
    {
        try {
            $plugins = PolarisConfig::plugins($this->container, $this->env);
        } catch (Throwable $exception) {
            return CheckResult::error($this->name(), $exception->getMessage(), 'Fix POLARIS_PLUGINS or the Univeros\Polaris\Plugins binding.');
        }
        if ($plugins === []) {
            return CheckResult::ok($this->name(), 'No plugin configured.');
        }
        $prefix = rtrim(PolarisConfig::pathPrefix($this->env), '/');
        $problems = [];
        foreach ($plugins as $plugin) {
            $baseUrl = self::baseUrl($plugin);
            $path = $baseUrl === null ? null : rtrim((string) parse_url($baseUrl, PHP_URL_PATH), '/');
            if ($path !== null && $path !== $prefix) {
                $problems[] = sprintf('%s: baseUrl %s is not where POLARIS_PATH_PREFIX mounts Polaris (%s)', $plugin->id(), $baseUrl, $prefix === '' ? '/' : $prefix);
            }
        }
        if ($problems !== []) {
            return CheckResult::error($this->name(), implode('; ', $problems), 'Give each plugin the URL Polaris is mounted at, prefix included.');
        }

        return CheckResult::ok($this->name(), sprintf('%d plugin(s): %s.', count($plugins), implode(', ', array_map(static fn(Plugin $plugin): string => $plugin->id(), $plugins))));
    }

    /**
     * ponytail: plugins expose their baseUrl unevenly (`baseUrl()`, `settings()->baseUrl`); sso and scim
     * keep it private and go unchecked until polaris-core gives plugins one accessor.
     */
    private static function baseUrl(Plugin $plugin): ?string
    {
        if (method_exists($plugin, 'baseUrl')) {
            $url = $plugin->baseUrl();

            return is_string($url) ? $url : null;
        }
        $settings = method_exists($plugin, 'settings') ? $plugin->settings() : null;

        return is_object($settings) && property_exists($settings, 'baseUrl') && is_string($settings->baseUrl) ? $settings->baseUrl : null;
    }
}
