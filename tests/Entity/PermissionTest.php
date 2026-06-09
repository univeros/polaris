<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\Permission;

final class PermissionTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $permission = new Permission();

        self::assertSame('', $permission->id);
        self::assertSame('', $permission->key);
        self::assertSame('', $permission->description);
    }
}
