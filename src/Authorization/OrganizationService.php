<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Organization;
use Univeros\Polaris\Entity\Permission;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\RolePermission;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\OrganizationCreated;
use Univeros\Polaris\Event\OrganizationDeleted;
use Univeros\Polaris\Event\OrganizationUpdated;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Exception\OrganizationSlugConflictException;

use function mb_strlen;
use function preg_replace;
use function strtolower;
use function trim;

/**
 * Creates and lists organizations.
 *
 * Creating one is all-or-nothing: it persists the org, clones the owner/admin/member system role
 * templates into org-scoped roles (with their permission grants), and grants the creator an active
 * `owner` membership — all committed in a single unit-of-work flush — then emits
 * {@see OrganizationCreated}. See `docs/auth/rbac.md` §3 and §6.
 */
final class OrganizationService
{
    /**
     * @param RepositoryInterface<Organization> $organizations
     * @param RepositoryInterface<Membership>   $memberships
     * @param RepositoryInterface<Permission>   $permissions
     */
    public function __construct(
        private readonly RepositoryInterface $organizations,
        private readonly RepositoryInterface $memberships,
        private readonly RepositoryInterface $permissions,
        private readonly PermissionCatalog $catalog,
        private readonly SessionService $sessions,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Create an organization owned by the given user.
     *
     * @throws InvalidArgumentException when no URL-safe slug can be derived from the name
     * @throws OrganizationSlugConflictException when the slug is already taken
     */
    public function create(string $name, ?string $slug, string $userId): Organization
    {
        $slug = $this->resolveSlug($name, $slug);

        // Suspended (soft-deleted) orgs keep their slug locked until the retention purge —
        // releasing it earlier would let a stranger take over the identity of a restorable org.
        if ($this->organizations->findOneBy(['slug' => $slug]) !== null) {
            throw new OrganizationSlugConflictException($slug);
        }

        $now = $this->clock->now();

        $organization = new Organization();
        $organization->id = Uuid::v7()->toRfc4122();
        $organization->name = $name;
        $organization->slug = $slug;
        $organization->status = Organization::STATUS_ACTIVE;
        $organization->createdBy = $userId;
        $organization->createdAt = $now;
        $organization->updatedAt = $now;
        $this->unitOfWork->persist($organization);

        $ownerRoleId = $this->cloneRoleTemplates($organization->id, $now);

        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = $userId;
        $membership->organizationId = $organization->id;
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->joinedAt = $now;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        $this->unitOfWork->persist($membership);

        $grant = new MembershipRole();
        $grant->membershipId = $membership->id;
        $grant->roleId = $ownerRoleId;
        $this->unitOfWork->persist($grant);

        $this->unitOfWork->flush();

        $this->events->dispatch(new OrganizationCreated($organization->id, $organization->slug, $userId));

        return $organization;
    }

    /**
     * The organizations the user is an active member of.
     *
     * @return list<Organization>
     */
    public function listForUser(string $userId): array
    {
        $organizations = [];
        foreach ($this->memberships->findBy(['userId' => $userId, 'status' => Membership::STATUS_ACTIVE]) as $membership) {
            $organization = $this->organizations->find($membership->organizationId);
            if ($organization instanceof Organization && $organization->status === Organization::STATUS_ACTIVE) {
                $organizations[] = $organization;
            }
        }

        return $organizations;
    }

    /**
     * Rename the organization. Emits `org.updated` (issue #90).
     *
     * @throws InvalidArgumentException empty or over-long name
     */
    public function update(Organization $organization, string $name, string $actorUserId): Organization
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 160) {
            throw new InvalidArgumentException('A name of 1-160 characters is required.');
        }

        $organization->name = $name;
        $organization->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($organization);
        $this->unitOfWork->flush();

        $this->events->dispatch(new OrganizationUpdated($organization->id, $actorUserId));

        return $organization;
    }

    /**
     * Soft-delete the organization (`docs/auth/rbac.md` §6): `status=suspended`, which strips every
     * member's org authority on their next resolution (the PermissionResolver skips suspended
     * orgs), hides it from listings, and blocks switch-org. Rows are purged later per retention
     * policy (ops tooling). Idempotent: already-suspended orgs emit no second event.
     */
    public function softDelete(Organization $organization, string $actorUserId): void
    {
        if ($organization->status === Organization::STATUS_SUSPENDED) {
            return;
        }

        $organization->status = Organization::STATUS_SUSPENDED;
        $organization->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($organization);
        $this->unitOfWork->flush();

        // Cut every member's org-scoped sessions, mirroring member suspension (#82): without
        // this, refresh tokens pointed at the dead org keep rotating into empty-authority tokens.
        foreach ($this->memberships->findBy(['organizationId' => $organization->id]) as $membership) {
            $this->sessions->revokeAllForOrganization($membership->userId, $organization->id, RefreshToken::REASON_ADMIN);
        }

        $this->events->dispatch(new OrganizationDeleted($organization->id, $actorUserId));
    }

    /**
     * Clone the owner/admin/member templates into org-scoped roles (with their grants) and return
     * the id of the cloned `owner` role. `superadmin` is a system role and is never cloned.
     */
    private function cloneRoleTemplates(string $organizationId, DateTimeImmutable $now): string
    {
        $permissionIds = $this->permissionIdsByKey();
        $ownerRoleId = '';

        foreach ($this->catalog->roleTemplates() as $template) {
            if ($template->slug === PermissionCatalog::ROLE_SUPERADMIN) {
                continue;
            }

            $role = new Role();
            $role->id = Uuid::v7()->toRfc4122();
            $role->organizationId = $organizationId;
            $role->name = $template->name;
            $role->slug = $template->slug;
            $role->description = $template->description;
            $role->isSystem = false; // cloned roles are tenant-owned and editable
            $role->createdAt = $now;
            $role->updatedAt = $now;
            $this->unitOfWork->persist($role);

            if ($template->slug === PermissionCatalog::ROLE_OWNER) {
                $ownerRoleId = $role->id;
            }

            foreach ($template->permissionKeys as $key) {
                $permissionId = $permissionIds[$key] ?? null;
                if ($permissionId !== null) {
                    $grant = new RolePermission();
                    $grant->roleId = $role->id;
                    $grant->permissionId = $permissionId;
                    $this->unitOfWork->persist($grant);
                }
            }
        }

        return $ownerRoleId;
    }

    /**
     * @return array<string, string> permission key => id
     */
    private function permissionIdsByKey(): array
    {
        $map = [];
        foreach ($this->permissions->findAll() as $permission) {
            $map[$permission->key] = $permission->id;
        }

        return $map;
    }

    private function resolveSlug(string $name, ?string $slug): string
    {
        if ($slug !== null && $slug !== '') {
            return $slug;
        }

        $derived = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($name)), '-');
        if ($derived === '') {
            throw new InvalidArgumentException('A URL-safe slug could not be derived from the name; provide one.');
        }

        return $derived;
    }
}
