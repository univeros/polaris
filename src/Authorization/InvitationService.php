<?php

declare(strict_types=1);

namespace Univeros\Polaris\Authorization;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateInterval;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\Invitation;
use Univeros\Polaris\Entity\Membership;
use Univeros\Polaris\Entity\Organization;
use Univeros\Polaris\Entity\MembershipRole;
use Univeros\Polaris\Entity\Role;
use Univeros\Polaris\Entity\User;
use Univeros\Polaris\Event\MemberInvited;
use Univeros\Polaris\Event\MemberJoined;
use Univeros\Polaris\Exception\AlreadyMemberException;
use Univeros\Polaris\Exception\AuthorizationException;
use Univeros\Polaris\Exception\InvalidInvitationTokenException;
use Univeros\Polaris\Exception\InvitationNotFoundException;
use Univeros\Polaris\Identity\EmailNormalizer;
use Univeros\Polaris\Security\Pepper;

use function base64_encode;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function random_bytes;
use function rtrim;
use function strtr;

use const DATE_ATOM;

/**
 * Issues, lists, revokes, and accepts organization invitations (`docs/auth/rbac.md` §7).
 *
 * The invitee may not yet have an account: the invite is keyed by email, and the emailed token is
 * a 256-bit CSPRNG secret whose keyed HMAC hash ({@see Pepper}) is the only thing stored — the
 * plaintext travels once on the {@see MemberInvited} event for the mailer. Invariants: an
 * already-active member cannot be invited (a pending invite is refreshed idempotently, rotating
 * the token), a suspended member can be neither invited nor reactivated by accepting (lifting a
 * suspension is an explicit `members.update` status change), and the inviter cannot grant roles
 * above their own authority ({@see EscalationGuard}). Acceptance enforces the email match and is
 * single use; roles are granted additively to any the member already holds.
 *
 * The escalation check runs at **invite time** against the inviter's then-current authority — a
 * deliberate snapshot: demoting the inviter does not retract their outstanding (≤7d) invitations;
 * revoke them explicitly if that matters.
 */
final class InvitationService
{
    private const string PEPPER_CONTEXT = 'org_invite';
    private const int TTL_SECONDS = 604800; // 7 days
    private const int SECRET_BYTES = 32;

    /**
     * @param RepositoryInterface<Invitation>     $invitations
     * @param RepositoryInterface<Organization>   $organizations
     * @param RepositoryInterface<Membership>     $memberships
     * @param RepositoryInterface<MembershipRole> $membershipRoles
     * @param RepositoryInterface<Role>           $roles
     * @param RepositoryInterface<User>           $users
     */
    public function __construct(
        private readonly RepositoryInterface $invitations,
        private readonly RepositoryInterface $organizations,
        private readonly RepositoryInterface $memberships,
        private readonly RepositoryInterface $membershipRoles,
        private readonly RepositoryInterface $roles,
        private readonly RepositoryInterface $users,
        private readonly PermissionResolver $resolver,
        private readonly EscalationGuard $escalation,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly Pepper $pepper,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Create an invitation (or refresh the pending one for the same email, rotating its token)
     * and announce it with the plaintext token for the mailer.
     *
     * @param list<string> $roleSlugs
     *
     * @return array<string, mixed> the created invitation: id, email, role_slugs, expires_at
     *
     * @throws InvalidArgumentException an unknown role slug, or no roles at all
     * @throws AlreadyMemberException   the email belongs to an active — or suspended — member
     * @throws AuthorizationException   the inviter cannot grant a requested role
     */
    public function invite(string $actorUserId, string $organizationId, string $email, array $roleSlugs): array
    {
        $email = EmailNormalizer::normalize($email);

        $roleIds = [];
        foreach ($roleSlugs as $slug) {
            $role = $this->roles->findOneBy(['organizationId' => $organizationId, 'slug' => $slug]);
            if (!$role instanceof Role) {
                throw new InvalidArgumentException("Unknown role for this organization: $slug");
            }
            $roleIds[] = $role->id;
        }
        if ($roleIds === []) {
            throw new InvalidArgumentException('At least one role is required.');
        }

        $invitee = $this->users->findOneBy(['email' => $email]);
        if ($invitee instanceof User) {
            $membership = $this->memberships->findOneBy([
                'userId' => $invitee->id,
                'organizationId' => $organizationId,
            ]);
            if ($membership instanceof Membership && $membership->status === Membership::STATUS_ACTIVE) {
                throw new AlreadyMemberException('That user is already an active member of this organization.');
            }
            // A suspension must not be sidestepped by invite-and-accept; lifting it is an explicit
            // status change (members.update), not an invitation.
            if ($membership instanceof Membership && $membership->status === Membership::STATUS_SUSPENDED) {
                throw new AlreadyMemberException("That user's membership is suspended; reactivate it instead.");
            }
        }

        $actor = $this->resolver->resolve($actorUserId, $organizationId);
        $this->escalation->assertCanGrant($actor, $roleIds);

        $now = $this->clock->now();
        $token = $this->newToken();

        $invitation = $this->pendingFor($organizationId, $email) ?? new Invitation();
        if ($invitation->id === '') {
            $invitation->id = Uuid::v7()->toRfc4122();
            $invitation->organizationId = $organizationId;
            $invitation->email = $email;
            $invitation->createdAt = $now;
        }
        $invitation->roleIds = (string) json_encode($roleIds);
        $invitation->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $token);
        $invitation->invitedBy = $actorUserId;
        $invitation->expiresAt = $now->add(new DateInterval('PT' . self::TTL_SECONDS . 'S'));

        $this->unitOfWork->persist($invitation);
        $this->unitOfWork->flush();

        $this->events->dispatch(new MemberInvited($organizationId, $email, $actorUserId, $token));

        return [
            'id' => $invitation->id,
            'email' => $invitation->email,
            'role_slugs' => $roleSlugs,
            'expires_at' => $invitation->expiresAt->format(DATE_ATOM),
        ];
    }

    /**
     * The organization's pending (unaccepted, unexpired) invitations. An expired row is hidden —
     * re-inviting the same email recycles it with a fresh token and expiry.
     *
     * @return list<array<string, mixed>> each: id, email, role_slugs, invited_by, expires_at, created_at
     */
    public function listPending(string $organizationId): array
    {
        $now = $this->clock->now();

        $pending = [];
        foreach ($this->invitations->findBy(['organizationId' => $organizationId]) as $invitation) {
            if ($invitation->acceptedAt !== null || $invitation->expiresAt <= $now) {
                continue;
            }

            $pending[] = [
                'id' => $invitation->id,
                'email' => $invitation->email,
                'role_slugs' => $this->slugsOf($this->decodeRoleIds($invitation)),
                'invited_by' => $invitation->invitedBy,
                'expires_at' => $invitation->expiresAt->format(DATE_ATOM),
                'created_at' => $invitation->createdAt->format(DATE_ATOM),
            ];
        }

        return $pending;
    }

    /**
     * Revoke (delete) a pending invitation.
     *
     * @throws InvitationNotFoundException unknown id, another org's invitation, or already accepted
     */
    public function revoke(string $organizationId, string $invitationId): void
    {
        $invitation = $this->invitations->find($invitationId);
        if (
            !$invitation instanceof Invitation
            || $invitation->organizationId !== $organizationId
            || $invitation->acceptedAt !== null
        ) {
            throw new InvitationNotFoundException('No such pending invitation.');
        }

        $this->unitOfWork->remove($invitation);
        $this->unitOfWork->flush();
    }

    /**
     * Accept an invitation: activate (or create) the caller's membership with the invited roles.
     * Single use; the caller's email must match the invitee's.
     *
     * @return string the organization id joined
     *
     * @throws InvalidInvitationTokenException unknown, consumed, or expired token
     * @throws AuthorizationException          email mismatch, or the caller's membership is suspended
     */
    public function accept(string $userId, string $token): string
    {
        $invitation = $this->invitations->findOneBy([
            'tokenHash' => $this->pepper->hash(self::PEPPER_CONTEXT, $token),
        ]);
        if (!$invitation instanceof Invitation) {
            throw new InvalidInvitationTokenException('The invitation is invalid or has expired.');
        }

        $now = $this->clock->now();
        if ($invitation->acceptedAt !== null || $invitation->expiresAt <= $now) {
            throw new InvalidInvitationTokenException('The invitation is invalid or has expired.');
        }

        // An invitation into a soft-deleted org must not create membership rows that would go
        // live on a restore; the response is deliberately indistinguishable from a bad token.
        $organization = $this->organizations->find($invitation->organizationId);
        if (!$organization instanceof Organization || $organization->status !== Organization::STATUS_ACTIVE) {
            throw new InvalidInvitationTokenException('The invitation is invalid or has expired.');
        }

        $user = $this->users->find($userId);
        if (!$user instanceof User) {
            throw new InvalidInvitationTokenException('The invitation is invalid or has expired.');
        }
        if (EmailNormalizer::normalize($user->email) !== $invitation->email) {
            throw new AuthorizationException('The invitation was issued to a different email address.');
        }

        $membership = $this->memberships->findOneBy([
            'userId' => $userId,
            'organizationId' => $invitation->organizationId,
        ]);
        if ($membership instanceof Membership && $membership->status === Membership::STATUS_SUSPENDED) {
            // An invitation (even one issued before the suspension) must not lift a suspension;
            // only an explicit status change by someone with members.update may.
            throw new AuthorizationException('Your membership in this organization is suspended.');
        }
        if (!$membership instanceof Membership) {
            $membership = new Membership();
            $membership->id = Uuid::v7()->toRfc4122();
            $membership->userId = $userId;
            $membership->organizationId = $invitation->organizationId;
            $membership->invitedBy = $invitation->invitedBy;
            $membership->createdAt = $now;
        }
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->joinedAt ??= $now;
        $membership->updatedAt = $now;
        $this->unitOfWork->persist($membership);

        $held = [];
        foreach ($this->membershipRoles->findBy(['membershipId' => $membership->id]) as $link) {
            $held[$link->roleId] = true;
        }
        foreach ($this->decodeRoleIds($invitation) as $roleId) {
            // A role may have been deleted between invite and accept; grant what still exists.
            if (!isset($held[$roleId]) && $this->roles->find($roleId) instanceof Role) {
                $link = new MembershipRole();
                $link->membershipId = $membership->id;
                $link->roleId = $roleId;
                $this->unitOfWork->persist($link);
            }
        }

        $invitation->acceptedAt = $now;
        $this->unitOfWork->persist($invitation);
        $this->unitOfWork->flush();

        $this->events->dispatch(new MemberJoined($invitation->organizationId, $userId, $user->email));

        return $invitation->organizationId;
    }

    private function pendingFor(string $organizationId, string $email): ?Invitation
    {
        foreach ($this->invitations->findBy(['organizationId' => $organizationId, 'email' => $email]) as $invitation) {
            if ($invitation->acceptedAt === null) {
                return $invitation;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function decodeRoleIds(Invitation $invitation): array
    {
        $decoded = json_decode($invitation->roleIds, true);
        if (!is_array($decoded)) {
            return [];
        }

        $roleIds = [];
        foreach ($decoded as $roleId) {
            if (is_string($roleId)) {
                $roleIds[] = $roleId;
            }
        }

        return $roleIds;
    }

    /**
     * @param list<string> $roleIds
     *
     * @return list<string>
     */
    private function slugsOf(array $roleIds): array
    {
        $slugs = [];
        foreach ($roleIds as $roleId) {
            $role = $this->roles->find($roleId);
            if ($role instanceof Role) {
                $slugs[] = $role->slug;
            }
        }

        return $slugs;
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(self::SECRET_BYTES)), '+/', '-_'), '=');
    }
}
