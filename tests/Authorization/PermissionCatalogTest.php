<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Authorization;

use PHPUnit\Framework\TestCase;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\RoleTemplate;
use Univeros\Polaris\Contracts\PermissionContributorInterface;

use function array_column;
use function array_keys;

final class PermissionCatalogTest extends TestCase
{
    public function testListsTheV1Permissions(): void
    {
        $permissions = (new PermissionCatalog())->permissions();

        self::assertSame([
            'org.read',
            'org.update',
            'org.delete',
            'members.read',
            'members.invite',
            'members.update',
            'members.remove',
            'roles.read',
            'roles.manage',
            'users.read',
            'users.manage',
            'audit.read',
        ], array_keys($permissions));

        foreach ($permissions as $key => $description) {
            self::assertNotSame('', $description, "$key must have a description");
        }
    }

    public function testMergesHostContributedPermissions(): void
    {
        $contributor = new class implements PermissionContributorInterface {
            public function permissions(): array
            {
                return ['billing.manage' => 'Manage billing'];
            }
        };

        $permissions = (new PermissionCatalog([$contributor]))->permissions();

        self::assertArrayHasKey('billing.manage', $permissions);
        self::assertSame('Manage billing', $permissions['billing.manage']);
        self::assertArrayHasKey('org.read', $permissions, 'core permissions remain');
    }

    public function testSeedsFourSystemRoleTemplates(): void
    {
        $templates = (new PermissionCatalog())->roleTemplates();

        self::assertCount(4, $templates);
        self::assertSame(['owner', 'admin', 'member', 'superadmin'], array_column($templates, 'slug'));
    }

    public function testOwnerGetsEveryOrgPermissionButNotAdminScope(): void
    {
        $owner = $this->template('owner');

        self::assertContains('org.delete', $owner->permissionKeys);
        self::assertContains('audit.read', $owner->permissionKeys);
        self::assertNotContains('users.read', $owner->permissionKeys, 'users.* is admin scope, not an org permission');
        self::assertNotContains('users.manage', $owner->permissionKeys);
    }

    public function testAdminIsOwnerWithoutOrgDelete(): void
    {
        $admin = $this->template('admin');

        self::assertNotContains('org.delete', $admin->permissionKeys);
        self::assertContains('members.update', $admin->permissionKeys);
        self::assertContains('roles.manage', $admin->permissionKeys);
    }

    public function testMemberIsReadOnly(): void
    {
        self::assertSame(['org.read', 'members.read', 'roles.read'], $this->template('member')->permissionKeys);
    }

    public function testSuperadminGetsEveryPermission(): void
    {
        self::assertSame(
            array_keys((new PermissionCatalog())->permissions()),
            $this->template('superadmin')->permissionKeys,
        );
    }

    private function template(string $slug): RoleTemplate
    {
        foreach ((new PermissionCatalog())->roleTemplates() as $template) {
            if ($template->slug === $slug) {
                return $template;
            }
        }

        self::fail("No role template for slug $slug");
    }
}
