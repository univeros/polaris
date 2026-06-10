# Domain Events

Polaris emits **PSR-14 events** on the framework's Happen dispatcher for every
significant identity action. Events decouple side effects (sending emails/SMS,
writing the audit log, host integrations) from the domain services that raise
them. A host subscribes listeners via `listeners:list` / its config; Polaris
ships the audit-log, metrics, and notification listeners and lets hosts add
their own.

Every event class lives in `Univeros\Polaris\Event\` and exposes its dotted
name as a `NAME` constant. The payload columns below are the constructor
properties, in order.

## Conventions

- Event names are dotted, past-tense: `resource.action`.
- Each event is an **immutable readonly DTO** carrying ids and non-secret context
  only. Events that participate in a secret-bearing flow (`user.registered`,
  `user.password_reset_requested`, `member.invited`) do carry the one-time token
  so the notification listener can send it, but the audit listener never writes
  it: the audit metadata is an explicit whitelist.
- Events are dispatched **after** the domain transaction commits (so listeners
  never act on rolled-back state), except `*_failed` events, which are
  informational.
- `ip` and `ua` (user agent) come from the request's `ClientContext`. The user
  agent is sanitized and bounded at the edge by `ClientContextMiddleware`.

---

## Catalog

### Identity & lifecycle

| Event                            | Payload (ids + context)                  | Typical listeners            |
| -------------------------------- | ---------------------------------------- | ---------------------------- |
| `user.registered`                | userId, email, verificationToken*        | send verification, audit     |
| `user.email_verified`            | userId, email                            | audit                        |
| `user.logged_in`                 | userId, sid, ip, ua, amr                 | audit                        |
| `user.login_failed`              | userId, ip, ua, reason                   | audit, alerting              |
| `user.locked`                    | userId, ip, until                        | audit, alerting, notify user |
| `user.password_changed`          | userId, method (reset\|change)           | audit, notify user           |
| `user.password_reset_requested`  | userId, email, resetToken*               | send reset, audit            |
| `user.disabled` / `user.enabled` | userId, actorUserId                      | audit                        |
| `user.deleted`                   | userId (tombstone), actorUserId          | audit                        |

\* secret: delivered by the notification listener, never written to the audit log.

Notes:

- `user.logged_in` fires once per completed login: on the password-only path,
  or after the MFA gate clears. `amr` records the methods (`["pwd"]` or
  `["pwd","otp"]`). It carries no org context; a session is scoped to an org
  later via `auth.org_switched`.
- `user.login_failed` fires only for a known, active, not-currently-locked
  account (no account-existence oracle). `reason` is currently always
  `invalid_credentials`.
- `user.locked` carries `until`, the lock expiry instant.

### Tokens & sessions

| Event                         | Payload                          | Listeners            |
| ----------------------------- | -------------------------------- | -------------------- |
| `auth.token_refreshed`        | userId, familyId                 | audit (debug)        |
| `auth.refresh_reuse_detected` | userId, familyId, ip, ua         | **audit + alerting** |
| `auth.sessions_revoked`       | userId, ip, count, reason        | audit                |
| `auth.org_switched`           | userId, fromOrgId, toOrgId       | audit                |

Notes:

- `familyId` is the session id (the `sid` claim): one refresh-token family is
  one session.
- `auth.sessions_revoked` is emitted by logout-all, with `count` (revoked
  sessions) and `reason`. The password reset/change flows also revoke sessions
  (logout everywhere) but emit only `user.password_changed`; subscribe to that
  event when you need to observe credential-change revocations.

### MFA / OTP

| Event                      | Payload                                   | Listeners           |
| -------------------------- | ----------------------------------------- | ------------------- |
| `mfa.enrolled`             | userId, factorId, type                    | audit, notify user  |
| `mfa.factor_removed`       | userId, factorId                          | audit, notify user  |
| `mfa.verified`             | userId, factorId (null for recovery)      | audit               |
| `mfa.verify_failed`        | userId, factorId, type                    | audit, alerting     |
| `mfa.step_up_completed`    | userId, sessionId                         | audit               |
| `otp.sent`                 | userId, factorId, channel                 | audit (rate-watch)  |
| `otp.verify_failed`        | userId, factorId, attemptsLeft            | audit, alerting     |
| `mfa.recovery_regenerated` | userId                                    | audit, notify user  |
| `mfa.recovery_used`        | userId, remaining                         | audit, notify user  |

Notes:

- `mfa.enrolled` fires when the user confirms their **first** factor (the
  moment MFA starts protecting the account), with the factor `type`
  (`totp`/`sms`/`email`).
- `mfa.verify_failed` is the gate-level signal (login MFA and step-up): it
  carries the attempted `factorId` and its `type`; `type` is `recovery` on the
  factor-less recovery-code path and null for an unknown or unconfirmed factor
  (the audit row discloses nothing the generic API failure does not).
- `otp.verify_failed` is the channel-level signal for sms/email codes and
  carries `attemptsLeft`, the remaining attempt budget for the live challenge.
- A recovery batch is always `RecoveryCodeService::COUNT` (10) codes, so
  `mfa.recovery_regenerated` needs no count.

### Organizations & RBAC

| Event                   | Payload                                | Listeners          |
| ----------------------- | -------------------------------------- | ------------------ |
| `org.created`           | orgId, slug, ownerUserId               | audit              |
| `org.updated`           | orgId, actorUserId                     | audit              |
| `org.deleted`           | orgId, actorUserId                     | audit, alerting    |
| `member.invited`        | orgId, email, invitedBy, inviteToken*  | send invite, audit |
| `member.joined`         | orgId, userId, email                   | audit              |
| `member.roles_changed`  | orgId, userId, roleSlugs, actorUserId  | audit              |
| `member.status_changed` | orgId, userId, status, actorUserId     | audit              |
| `member.removed`        | orgId, userId, actorUserId             | audit              |
| `role.created`          | orgId, roleId, actorUserId             | audit              |
| `role.updated`          | orgId, roleId, actorUserId             | audit              |
| `role.deleted`          | orgId, roleId, actorUserId             | audit              |

\* secret: delivered by the notification listener, never written to the audit log.

Notes:

- `member.status_changed` covers suspension **and** reactivation; `status` is
  `suspended` or `active`.
- `org.deleted` is the soft delete (`status=suspended`); it is idempotent and
  fires once.

---

## Listener wiring

```php
// Polaris ships these; hosts may add more.
bin/altair listeners:list --format=json          # inspect what's subscribed
bin/altair listeners:show auth.refresh_reuse_detected
```

- `AuditLogListener` writes one append-only `auth_audit_log` row per event:
  the event name, the actor and org context, `ip`/`user_agent` where the event
  carries them, and a whitelisted metadata blob. Unknown events are ignored,
  and a failed audit write is logged and swallowed (fail-open: audit loss must
  not break the user-facing operation).
- `MetricsListener` increments the `polaris.auth.events` counter for every
  Polaris event, with the event name as an attribute.
- `NotificationListener` subscribes to the user-facing ones
  (`user.registered`, `user.password_reset_requested`, `member.invited`,
  `user.locked`, the `mfa.*` lifecycle events) and calls the
  `OtpMailerInterface` / `SmsSenderInterface` ports.
- Hosts add listeners (e.g. push `user.registered` to a CRM, alert on
  `auth.refresh_reuse_detected`) without touching Polaris.

> The notification *content/templates* are the host's concern via the
> `OtpMailerInterface` template name + context; Polaris defines the event and
> the data, not the copy.
