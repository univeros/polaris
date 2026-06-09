<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Univeros\Polaris\Contracts\PermissionContributorInterface;

use function array_diff;
use function array_keys;
use function array_values;

/**
 * The code-defined permission catalog — the single source of truth for authorization.
 *
 * Polaris owns the identity/tenant permissions enumerated here; a host can extend the catalog with
 * its own keys through {@see PermissionContributorInterface}. The seed migration reads this catalog
 * to populate `auth_permissions` and the system role templates (owner/admin/member/superadmin),
 * so the database always reflects the code. See `docs/auth/rbac.md`.
 */
final class PermissionCatalog
{
    /** Permission keys (`resource.action`). */
    public const string ORG_READ = 'org.read';
    public const string ORG_UPDATE = 'org.update';
    public const string ORG_DELETE = 'org.delete';
    public const string MEMBERS_READ = 'members.read';
    public const string MEMBERS_INVITE = 'members.invite';
    public const string MEMBERS_UPDATE = 'members.update';
    public const string MEMBERS_REMOVE = 'members.remove';
    public const string ROLES_READ = 'roles.read';
    public const string ROLES_MANAGE = 'roles.manage';
    public const string USERS_READ = 'users.read';
    public const string USERS_MANAGE = 'users.manage';
    public const string AUDIT_READ = 'audit.read';

    /** System role slugs. */
    public const string ROLE_OWNER = 'owner';
    public const string ROLE_ADMIN = 'admin';
    public const string ROLE_MEMBER = 'member';
    public const string ROLE_SUPERADMIN = 'superadmin';

    /**
     * The v1 catalog: key => description.
     *
     * @var array<string, string>
     */
    private const array CORE_PERMISSIONS = [
        self::ORG_READ => 'View the organization profile',
        self::ORG_UPDATE => 'Edit organization name and settings',
        self::ORG_DELETE => 'Delete the organization',
        self::MEMBERS_READ => 'List organization members',
        self::MEMBERS_INVITE => 'Send membership invitations',
        self::MEMBERS_UPDATE => "Change a member's roles or suspend them",
        self::MEMBERS_REMOVE => 'Remove a member from the organization',
        self::ROLES_READ => 'List roles',
        self::ROLES_MANAGE => 'Create, update and delete custom roles and assignments',
        self::USERS_READ => 'Read user records (admin scope)',
        self::USERS_MANAGE => 'Disable and enable users (admin scope)',
        self::AUDIT_READ => "Read the organization's audit log",
    ];

    /**
     * Cross-org/platform-admin permissions — not granted to org roles, only to `superadmin`.
     *
     * @var list<string>
     */
    private const array ADMIN_SCOPED = [self::USERS_READ, self::USERS_MANAGE];

    /** @var iterable<PermissionContributorInterface> */
    private readonly iterable $contributors;

    /**
     * @param iterable<PermissionContributorInterface> $contributors host modules extending the catalog
     */
    public function __construct(iterable $contributors = [])
    {
        $this->contributors = $contributors;
    }

    /**
     * The full catalog: core permissions plus any host contributions (host keys win on collision).
     *
     * @return array<string, string> key => description
     */
    public function permissions(): array
    {
        $permissions = self::CORE_PERMISSIONS;
        foreach ($this->contributors as $contributor) {
            foreach ($contributor->permissions() as $key => $description) {
                $permissions[$key] = $description;
            }
        }

        return $permissions;
    }

    /**
     * The seeded system role templates, in seed order.
     *
     * @return list<RoleTemplate>
     */
    public function roleTemplates(): array
    {
        $orgScoped = array_values(array_diff(array_keys(self::CORE_PERMISSIONS), self::ADMIN_SCOPED));
        $adminScoped = array_values(array_diff($orgScoped, [self::ORG_DELETE]));

        return [
            new RoleTemplate(
                self::ROLE_OWNER,
                'Owner',
                'Full control of the organization, including deletion and ownership transfer',
                $orgScoped,
            ),
            new RoleTemplate(
                self::ROLE_ADMIN,
                'Administrator',
                'Manage the organization and its members, but cannot delete it or transfer ownership',
                $adminScoped,
            ),
            new RoleTemplate(
                self::ROLE_MEMBER,
                'Member',
                'Read-only access to the organization, its members and roles',
                [self::ORG_READ, self::MEMBERS_READ, self::ROLES_READ],
            ),
            new RoleTemplate(
                self::ROLE_SUPERADMIN,
                'Super Admin',
                'Platform operator with a global override across all organizations',
                array_keys(self::CORE_PERMISSIONS),
            ),
        ];
    }
}
