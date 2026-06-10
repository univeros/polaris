# Authorization: Organizations & RBAC

Polaris is **multi-tenant**: identity (a `User`) is global, but authority is
scoped to an **organization** via a **membership** that carries **roles**, and
roles bundle **permissions**. A user is always acting within one *active org*
(the `org` claim); permission checks resolve against that org.

```
User ──< Membership >── Organization
              │
              └──< MembershipRole >── Role ──< RolePermission >── Permission
```

---

## 1. Concepts

- **Organization**: a tenant boundary. Owns its members, roles (beyond the
  system templates), invitations, and resources.
- **Membership**: the user's relationship to one org (`invited`/`active`/
  `suspended`). Deleting it removes all the user's authority in that org.
- **Role**: a named bundle of permissions, scoped to an org (or a **system
  role** when `organization_id IS NULL`). A membership can hold several roles;
  effective permissions are the **union**.
- **Permission**: an atomic capability keyed `resource.action`
  (e.g. `members.invite`). The catalog is code-defined (single source of truth)
  and seeded into `auth_permissions`.

---

## 2. Permission catalog

Defined once in code as a `PermissionCatalog` registry (the seed migration reads
it). v1 catalog:

| Key                    | Guards                                             |
| ---------------------- | -------------------------------------------------- |
| `org.read`             | view org profile                                   |
| `org.update`           | edit org name/settings                             |
| `org.delete`           | delete the org                                      |
| `members.read`         | list members                                       |
| `members.invite`       | send invitations                                   |
| `members.update`       | change a member's roles / suspend                  |
| `members.remove`       | remove a member                                    |
| `roles.read`           | list roles                                         |
| `roles.manage`         | create/update/delete custom roles + assignments    |
| `users.read`           | read user records (admin scope)                    |
| `users.manage`         | disable/enable users (admin scope)                 |
| `audit.read`           | read the org's audit log                           |

> The catalog is **extensible by the host**: a host module can contribute extra
> permission keys (e.g. `billing.manage`) via a `PermissionContributorInterface`,
> and attach them to roles. Polaris owns only the identity/tenant permissions
> above.

---

## 3. System role templates

Seeded on migrate. Per-org roles are **cloned from templates** when an org is
created, so each org can later customize its own copy without affecting others.

| Role         | Scope   | Permissions                                                       |
| ------------ | ------- | ---------------------------------------------------------------- |
| `owner`      | per-org | **all** org permissions, incl. `org.delete`, ownership transfer  |
| `admin`      | per-org | everything except `org.delete` / ownership transfer              |
| `member`     | per-org | `org.read`, `members.read`, `roles.read`                          |
| `superadmin` | system  | global override; bypasses org checks (platform operators)         |

Rules:

- The org **creator** is granted `owner` on creation. An org must always have
  **≥1 owner**; the last owner cannot be removed/demoted (enforced in the
  membership domain service).
- `superadmin` is a system role (`organization_id NULL`) assigned out-of-band
  (seed/admin tooling), never self-granted via the API.
- Custom roles (`is_system=false`) are created per-org via `roles.manage` and may
  only reference permissions the org is allowed to use.

---

## 4. Resolving effective permissions

On token issuance (login, refresh, org-switch), Polaris resolves the user's
authority **for the active org**:

```
effective_permissions(user, org) =
    if user has system role superadmin → ALL
    else  ∪ over (membership.roles for that org) of role.permissions
```

A `PermissionResolver` domain service performs this with a single query
(memberships→roles→permissions joined) and caches per-request. The result is:

- embedded in the access token as `roles` (slugs), which is compact and the default; and/or
- as `scope` (flattened permission keys) when `security.access_token.embed_scope`
  is true (larger token, zero server lookups on check).

When only `roles` are embedded, the `AuthorizationMiddleware` expands roles →
permissions via a short-TTL cache keyed by `(org, role-set)` so checks stay O(1)
without bloating the token.

---

## 5. Enforcement

Two complementary mechanisms:

### a) Declarative, at the HTTP edge

Actions declare what they need; an action-aware `AuthorizationMiddleware`
(priority `MiddlewarePriority::DISPATCHER + 10`, after routing, before the
action) enforces it before the domain runs:

```php
final class InviteMemberAction extends Action
{
    public const array REQUIRES_PERMISSIONS = ['members.invite'];
    public const bool   REQUIRES_STEP_UP    = false;
    // …domain/input/responder wiring…
}
```

The middleware reads the validated token from the request
(`TokenInterface::TOKEN_KEY`), resolves effective permissions for the `org`
claim, and:

- missing token → `401`,
- token present but lacking a required permission → `403 forbidden`,
- org mismatch (path org ≠ token org) → `403` (or triggers an implicit
  switch-org check; default deny),
- step-up stale when `REQUIRES_STEP_UP` → `401 step_up_required`.

### b) Programmatic, in the domain

For row-level / conditional checks a service injects a `Gate`:

```php
$this->gate->authorize($token, 'members.remove', $targetMembership);
// throws AuthorizationException (→ 403) when denied
```

The `Gate` also hosts **policy callbacks** for rules permissions alone can't
express (e.g. "can't remove the last owner", "admins can't modify owners").

> Path-vs-token org consistency is always checked: an endpoint under
> `/orgs/{id}/…` verifies `{id}` equals the active `org` claim (or that the user
> is `superadmin`), preventing a valid token for org A from acting on org B.

---

## 6. Organization lifecycle

- `POST /orgs {name, slug?}`: any authenticated, verified user may create an
  org; becomes `owner`. Slug auto-derived from name if omitted, uniqueness
  enforced. Emits `org.created`.
- `GET /orgs`: orgs the caller is an active member of.
- `GET /orgs/{id}`: `org.read`.
- `PATCH /orgs/{id}`: `org.update`.
- `DELETE /orgs/{id}`: `org.delete` + step-up; soft-delete (`status=suspended`)
  then purge per retention policy. Emits `org.deleted`.

---

## 7. Membership & invitations

```
POST /orgs/{id}/invites {email, role_slugs[]}    (perm: members.invite)
  → create auth_invitations row (7d), email an accept link/token
  → emit member.invited
  → invitee may or may not already have a Polaris account

POST /auth/invites/accept {token}                (authenticated)
  → validate token (unexpired, unaccepted)
  → if caller's email ≠ invite email → 403
  → create/activate membership with the invited roles
  → mark accepted, emit member.joined

GET    /orgs/{id}/members                         (perm: members.read)
PATCH  /orgs/{id}/members/{userId}/roles {role_slugs[]}  (perm: members.update)
DELETE /orgs/{id}/members/{userId}                (perm: members.remove)
```

Invariants enforced in the membership service:

- Cannot invite an already-active member (idempotent re-invite extends expiry).
- Cannot grant roles the inviter doesn't themselves possess (no privilege
  escalation) unless `superadmin`.
- Cannot remove or demote the **last owner**.
- An admin cannot modify an owner's roles (only an owner can).
- Suspending a membership immediately revokes that user's refresh tokens scoped
  to the org and strips org access on the next access-token refresh.

---

## 8. Roles management API

```
GET    /orgs/{id}/roles                 (roles.read)
POST   /orgs/{id}/roles                  (roles.manage)  {name, slug, permission_keys[]}
PATCH  /orgs/{id}/roles/{roleId}         (roles.manage)
DELETE /orgs/{id}/roles/{roleId}         (roles.manage)  (system roles immutable)
GET    /permissions                      (authenticated) (the catalog for UI building)
```

Custom roles may only reference permission keys available to the org
(Polaris catalog ∪ host-contributed). Deleting a role detaches it from all
memberships (cascade on `auth_membership_roles`).

---

## 9. Why this shape

- **Roles, not raw permissions, on memberships** → manageable at scale; admins
  reason about roles, the system computes permissions.
- **Per-org role copies** → tenants customize without cross-tenant blast radius;
  system templates give sane defaults instantly.
- **Permissions embedded in the access token (as roles)** → authorization is
  mostly stateless and fast; the short access-TTL bounds staleness, and refresh
  re-resolves so changes propagate within one window.
- **Gate + policies** → the 10% of rules that aren't expressible as a flat
  permission (last-owner, hierarchy) live in one auditable place.
