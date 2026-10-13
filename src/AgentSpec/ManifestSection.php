<?php

declare(strict_types=1);

namespace Univeros\Polaris\AgentSpec;

use Polaris\Http\Manifest\EndpointSpec;

use function array_map;
use function array_merge;
use function array_unique;
use function array_values;
use function implode;
use function rtrim;
use function sort;
use function sprintf;
use function str_replace;
use function strcmp;
use function usort;

/**
 * The Polaris section of the host's AgentSpec manifests (`.agent/modules/univeros/polaris.md`): the routes
 * core and the configured plugins serve, with their auth, step-up, permissions and errors, and the
 * permission catalog they require. Byte-stable for the same configuration, so the host's
 * `manifest:generate --check` holds.
 */
final class ManifestSection
{
    /**
     * @param list<EndpointSpec> $endpoints
     */
    public static function render(array $endpoints, string $prefix): string
    {
        usort($endpoints, static fn(EndpointSpec $a, EndpointSpec $b): int => strcmp($a->path . ' ' . $a->method, $b->path . ' ' . $b->method));
        $prefix = rtrim($prefix, '/');

        $lines = [
            '# univeros/polaris',
            '',
            'Polaris for PHP (authentication, MFA/OTP, sessions, organizations, RBAC) as a Univeros module.',
            '',
            '- These routes are served by `Univeros\\Polaris\\Http\\PolarisMiddleware` ahead of the router, not from `config/routes.php`. `bin/altair polaris:manifest --format=openapi` prints the full contract (inputs, outputs, examples).',
            sprintf('- Path prefix: %s (`POLARIS_PATH_PREFIX`).', $prefix === '' ? 'none' : '`' . $prefix . '`'),
            sprintf('- Plugins: %s.', self::plugins($endpoints)),
            '- Protect your own routes with `Altair\\Http\\Middleware\\TokenAuthenticationMiddleware` (Polaris access tokens, `Authorization: Bearer`) or `Univeros\\Polaris\\Http\\PluginTokenAuthenticationMiddleware` (plus the plugins\' credentials); authorize with `Polaris\\Authorization\\Gate`.',
            '- Errors are Polaris JSON envelopes; the codes below are the `error` field.',
            '',
            '## Routes',
            '',
            '| Method | Path | Auth | Permissions | Effect | Errors | Source |',
            '|---|---|---|---|---|---|---|',
        ];
        foreach ($endpoints as $spec) {
            $lines[] = sprintf(
                '| %s | `%s` | %s | %s | %s | %s | %s |',
                $spec->method,
                $prefix . $spec->path,
                $spec->auth . ($spec->stepUp ? ' + step-up' : ''),
                self::cell(implode(', ', $spec->requiresPermissions)),
                $spec->effect,
                self::cell(self::errors($spec)),
                $spec->plugin ?? 'core',
            );
        }

        $permissions = self::permissions($endpoints);
        if ($permissions !== []) {
            $lines = array_merge($lines, ['', '## Permissions', '', 'Required by the routes above (seeded into the catalog on install):', '']);
            foreach ($permissions as $permission) {
                $lines[] = '- `' . $permission . '`';
            }
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * @param list<EndpointSpec> $endpoints
     */
    private static function plugins(array $endpoints): string
    {
        $ids = [];
        foreach ($endpoints as $spec) {
            if ($spec->plugin !== null) {
                $ids[] = '`' . $spec->plugin . '`';
            }
        }
        $ids = array_values(array_unique($ids));
        sort($ids);

        return $ids === [] ? 'none' : implode(', ', $ids);
    }

    private static function errors(EndpointSpec $spec): string
    {
        return implode(', ', array_map(
            static fn(array $error): string => $error['code'] === null ? (string) $error['status'] : $error['status'] . ' ' . $error['code'],
            $spec->errors,
        ));
    }

    /**
     * @param list<EndpointSpec> $endpoints
     *
     * @return list<string>
     */
    private static function permissions(array $endpoints): array
    {
        $all = [];
        foreach ($endpoints as $spec) {
            $all = array_merge($all, $spec->requiresPermissions);
        }
        $all = array_values(array_unique($all));
        sort($all);

        return $all;
    }

    private static function cell(string $value): string
    {
        return str_replace('|', '\\|', $value);
    }
}
