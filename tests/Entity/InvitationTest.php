<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Entity;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Entity\Invitation;

final class InvitationTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $invitation = new Invitation();

        self::assertSame('', $invitation->id);
        self::assertSame('', $invitation->organizationId);
        self::assertSame('', $invitation->email);
        self::assertSame('[]', $invitation->roleIds);
        self::assertSame('', $invitation->tokenHash);
        self::assertSame('', $invitation->invitedBy);
        self::assertNull($invitation->acceptedAt);
    }
}
