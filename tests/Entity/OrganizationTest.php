<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\Organization;

final class OrganizationTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $organization = new Organization();

        self::assertSame('', $organization->id);
        self::assertSame('', $organization->name);
        self::assertSame('', $organization->slug);
        self::assertSame(Organization::STATUS_ACTIVE, $organization->status);
        self::assertSame('', $organization->createdBy);
    }

    public function testExposesTheStatusValues(): void
    {
        self::assertSame('active', Organization::STATUS_ACTIVE);
        self::assertSame('suspended', Organization::STATUS_SUSPENDED);
    }
}
