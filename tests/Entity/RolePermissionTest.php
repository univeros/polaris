<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\RolePermission;

final class RolePermissionTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $grant = new RolePermission();

        self::assertSame('', $grant->roleId);
        self::assertSame('', $grant->permissionId);
    }
}
