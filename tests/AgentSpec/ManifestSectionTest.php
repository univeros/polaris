<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\AgentSpec;

use Altair\Configuration\Support\Env;
use Altair\Container\Container;
use Altair\Module\Contracts\ManifestContributorInterface;
use PHPUnit\Framework\TestCase;
use Polaris\Username\UsernamePlugin;
use Univeros\Polaris\Module;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\ArrayEnv;

use function substr_count;

final class ManifestSectionTest extends TestCase
{
    public function testTheModuleContributesItsRoutesToTheHostsAgentManifests(): void
    {
        $module = new Module();
        $container = $this->container($module, ['POLARIS_PATH_PREFIX' => '/auth'], new Plugins(new UsernamePlugin()));

        $manifest = $module->manifest($container);

        self::assertInstanceOf(ManifestContributorInterface::class, $module);
        self::assertStringStartsWith("# univeros/polaris\n", $manifest);
        self::assertStringContainsString('- Path prefix: `/auth` (`POLARIS_PATH_PREFIX`).', $manifest);
        self::assertStringContainsString('- Plugins: `username`.', $manifest);
        self::assertMatchesRegularExpression('#\| POST \| `/auth/auth/login` \| public \| [^|]* \| write \| [^|]*401[^|]* \| core \|#', $manifest);
        self::assertStringContainsString('| `/auth/username/sign-in` |', $manifest);
        self::assertStringContainsString("\n## Permissions\n", $manifest);
        self::assertSame($manifest, $module->manifest($container), 'byte-stable for manifest:generate --check');
    }

    public function testWithoutPluginsOrPrefixItListsCoresRoutesOnly(): void
    {
        $module = new Module();
        $manifest = $module->manifest($this->container($module, [], null));

        self::assertStringContainsString('- Path prefix: none (`POLARIS_PATH_PREFIX`).', $manifest);
        self::assertStringContainsString('- Plugins: none.', $manifest);
        self::assertSame(52, substr_count($manifest, ' | core |'));
        self::assertNotEmpty($module->manifestDescription());
    }

    /**
     * @param array<string, string> $env
     */
    private function container(Module $module, array $env, ?Plugins $plugins): Container
    {
        $container = new Container();
        $container->instance(Env::class, new ArrayEnv($env));
        if ($plugins !== null) {
            $container->instance(Plugins::class, $plugins);
        }
        $module->apply($container);

        return $container;
    }
}
