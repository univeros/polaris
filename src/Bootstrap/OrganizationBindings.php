<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Authorization\EscalationGuard;
use Univeros\Polaris\Authorization\InvitationService;
use Univeros\Polaris\Authorization\MembershipService;
use Univeros\Polaris\Authorization\OrganizationService;
use Univeros\Polaris\Authorization\PermissionCatalog;
use Univeros\Polaris\Authorization\PermissionResolver;
use Univeros\Polaris\Authorization\RoleService;
use Univeros\Polaris\Http\Auth\AcceptInviteDomain;
use Univeros\Polaris\Http\Orgs\ChangeMemberRolesDomain;
use Univeros\Polaris\Http\Orgs\ChangeMemberStatusDomain;
use Univeros\Polaris\Http\Orgs\CreateInviteDomain;
use Univeros\Polaris\Http\Orgs\CreateOrganizationDomain;
use Univeros\Polaris\Http\Orgs\CreateRoleDomain;
use Univeros\Polaris\Http\Orgs\DeleteOrganizationDomain;
use Univeros\Polaris\Http\Orgs\DeleteRoleDomain;
use Univeros\Polaris\Http\Orgs\ListInvitesDomain;
use Univeros\Polaris\Http\Orgs\ListMembersDomain;
use Univeros\Polaris\Http\Orgs\ListOrganizationsDomain;
use Univeros\Polaris\Http\Orgs\ListPermissionsDomain;
use Univeros\Polaris\Http\Orgs\ListRolesDomain;
use Univeros\Polaris\Http\Orgs\ReadOrganizationDomain;
use Univeros\Polaris\Http\Orgs\RemoveMemberDomain;
use Univeros\Polaris\Http\Orgs\RevokeInviteDomain;
use Univeros\Polaris\Http\Orgs\UpdateOrganizationDomain;
use Univeros\Polaris\Http\Orgs\UpdateRoleDomain;
use Univeros\Polaris\Http\Users\DeleteUserDomain;
use Univeros\Polaris\Http\Users\DisableUserDomain;
use Univeros\Polaris\Http\Users\EnableUserDomain;
use Univeros\Polaris\Http\Users\ReadUserDomain;
use Univeros\Polaris\Http\Users\UpdateUserDomain;
use Univeros\Polaris\Identity\SessionService;
use Univeros\Polaris\Identity\UserAdminService;
use Univeros\Polaris\Persistence\EmailVerificationRepository;
use Univeros\Polaris\Persistence\InvitationRepository;
use Univeros\Polaris\Persistence\MembershipRepository;
use Univeros\Polaris\Persistence\MembershipRoleRepository;
use Univeros\Polaris\Persistence\MfaFactorRepository;
use Univeros\Polaris\Persistence\OrganizationRepository;
use Univeros\Polaris\Persistence\OtpChallengeRepository;
use Univeros\Polaris\Persistence\PasswordResetRepository;
use Univeros\Polaris\Persistence\PermissionRepository;
use Univeros\Polaris\Persistence\RolePermissionRepository;
use Univeros\Polaris\Persistence\RoleRepository;
use Univeros\Polaris\Persistence\UserRepository;
use Univeros\Polaris\Security\Pepper;

/**
 * Wires organization management: the org/membership/invitation/role services, user
 * administration, and the `/orgs`, `/permissions`, and `/users` domains.
 */
final class OrganizationBindings
{
    public function apply(Container $container): void
    {
        $this->bindOrganizations($container);
    }

    /**
     * Bind the organization service — a transactional create that clones the owner/admin/member
     * system role templates into org-scoped roles and grants the creator an active `owner`
     * membership — plus the `/orgs` domains. The repositories are autowired; the
     * {@see PermissionCatalog} is bound with no host contributors by default (a host may rebind it).
     */
    private function bindOrganizations(Container $container): void
    {
        $container->singleton(PermissionCatalog::class, static fn(): PermissionCatalog => new PermissionCatalog());

        $container->singleton(
            OrganizationService::class,
            static fn(
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                PermissionRepository $permissions,
                PermissionCatalog $catalog,
                SessionService $sessions,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): OrganizationService => new OrganizationService(
                $organizations,
                $memberships,
                $permissions,
                $catalog,
                $sessions,
                $unitOfWork,
                $clock,
                $events,
            ),
        );

        $container->singleton(CreateOrganizationDomain::class);
        $container->singleton(ListOrganizationsDomain::class);
        $container->singleton(
            ReadOrganizationDomain::class,
            static fn(OrganizationRepository $organizations): ReadOrganizationDomain
                => new ReadOrganizationDomain($organizations),
        );
        $container->singleton(UpdateOrganizationDomain::class);
        $container->singleton(DeleteOrganizationDomain::class);

        $container->singleton(
            EscalationGuard::class,
            static fn(
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
            ): EscalationGuard => new EscalationGuard($rolePermissions, $permissions),
        );

        $container->singleton(
            MembershipService::class,
            static fn(
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                UserRepository $users,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                SessionService $sessions,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): MembershipService => new MembershipService(
                $memberships,
                $membershipRoles,
                $roles,
                $users,
                $resolver,
                $escalation,
                $unitOfWork,
                $sessions,
                $clock,
                $events,
            ),
        );
        $container->singleton(ListMembersDomain::class);
        $container->singleton(ChangeMemberRolesDomain::class);
        $container->singleton(ChangeMemberStatusDomain::class);
        $container->singleton(RemoveMemberDomain::class);

        $container->singleton(
            InvitationService::class,
            static fn(
                InvitationRepository $invitations,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                UserRepository $users,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): InvitationService => new InvitationService(
                $invitations,
                $organizations,
                $memberships,
                $membershipRoles,
                $roles,
                $users,
                $resolver,
                $escalation,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );
        $container->singleton(CreateInviteDomain::class);
        $container->singleton(ListInvitesDomain::class);
        $container->singleton(RevokeInviteDomain::class);
        $container->singleton(AcceptInviteDomain::class);

        $container->singleton(
            RoleService::class,
            static fn(
                RoleRepository $roles,
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): RoleService => new RoleService(
                $roles,
                $rolePermissions,
                $permissions,
                $resolver,
                $escalation,
                $unitOfWork,
                $clock,
                $events,
            ),
        );
        $container->singleton(ListRolesDomain::class);
        $container->singleton(CreateRoleDomain::class);
        $container->singleton(UpdateRoleDomain::class);
        $container->singleton(DeleteRoleDomain::class);
        $container->singleton(ListPermissionsDomain::class);

        $container->singleton(
            UserAdminService::class,
            static fn(
                UserRepository $users,
                MfaFactorRepository $mfaFactors,
                OtpChallengeRepository $otpChallenges,
                EmailVerificationRepository $emailVerifications,
                PasswordResetRepository $passwordResets,
                PermissionResolver $resolver,
                SessionService $sessions,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): UserAdminService => new UserAdminService(
                $users,
                $mfaFactors,
                $otpChallenges,
                $emailVerifications,
                $passwordResets,
                $resolver,
                $sessions,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );
        $container->singleton(ReadUserDomain::class);
        $container->singleton(UpdateUserDomain::class);
        $container->singleton(DisableUserDomain::class);
        $container->singleton(EnableUserDomain::class);
        $container->singleton(DeleteUserDomain::class);
    }
}
