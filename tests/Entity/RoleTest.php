<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\Role;

final class RoleTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $role = new Role();

        self::assertSame('', $role->id);
        self::assertNull($role->organizationId);
        self::assertSame('', $role->name);
        self::assertSame('', $role->slug);
        self::assertNull($role->description);
        self::assertFalse($role->isSystem);
    }
}
