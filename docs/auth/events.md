# Domain Events

Polaris emits **PSR-14 events** on the framework's Happen dispatcher for every
significant identity action. Events decouple side effects (sending emails/SMS,
writing the audit log, host integrations) from the domain services that raise
them. A host subscribes listeners via `listeners:list` / its config; Polaris
ships the audit-log and notification listeners and lets hosts add their own.

## Conventions

- Event names are dotted, past-tense: `resource.action`.
- Each event is an **immutable readonly DTO** carrying ids and non-secret context
  only (never passwords, tokens, OTP codes, or secrets).
- Events are dispatched **after** the domain transaction commits (so listeners
  never act on rolled-back state), except `*_failed` events which are
  informational.
- The `AuditLogListener` subscribes to all of them and writes `auth_audit_log`;
  the `NotificationListener` subscribes to the user-facing ones and calls
  `OtpMailerInterface` / `SmsSenderInterface`.

---

## Catalog

### Identity & lifecycle

| Event                         | Payload (ids + context)                       | Typical listeners            |
| ----------------------------- | --------------------------------------------- | ---------------------------- |
| `user.registered`             | userId, email, ip                             | send verification, audit     |
| `user.email_verified`         | userId, email                                 | audit                        |
| `user.logged_in`              | userId, orgId, sid, ip, ua, amr               | audit                        |
| `user.login_failed`           | email(masked), ip, reason                     | audit, alerting              |
| `user.locked`                 | userId, until, ip                             | audit, alerting, notify user |
| `user.password_changed`       | userId, method (reset\|change)                | audit, notify user           |
| `user.password_reset_requested` | userId, ip                                  | send reset, audit            |
| `user.disabled` / `user.enabled` | userId, actorUserId                         | audit                        |
| `user.deleted`                | userId (tombstone), actorUserId               | audit                        |

### Tokens & sessions

| Event                          | Payload                              | Listeners            |
| ------------------------------ | ------------------------------------ | -------------------- |
| `auth.token_refreshed`         | userId, sid, familyId                | audit (debug)        |
| `auth.refresh_reuse_detected`  | userId, familyId, ip                 | **audit + alerting** |
| `auth.sessions_revoked`        | userId, count, reason                | audit                |
| `auth.org_switched`            | userId, fromOrgId, toOrgId           | audit                |

### MFA / OTP

| Event                     | Payload                                  | Listeners                |
| ------------------------- | ---------------------------------------- | ------------------------ |
| `mfa.enrolled`            | userId, factorId, type                   | audit, notify user       |
| `mfa.removed`             | userId, factorId, type                   | audit, notify user       |
| `mfa.verified`           | userId, factorId, type, purpose          | audit                    |
| `mfa.verify_failed`       | userId, factorId, type, attemptsLeft     | audit, alerting          |
| `otp.sent`                | userId, channel, destination(masked), purpose | audit (rate-watch)  |
| `mfa.recovery_regenerated`| userId, count                            | audit, notify user       |
| `mfa.recovery_used`       | userId, remaining                        | audit, notify user       |

### Organizations & RBAC

| Event                | Payload                                          | Listeners            |
| -------------------- | ------------------------------------------------ | -------------------- |
| `org.created`        | orgId, ownerUserId                               | audit                |
| `org.updated`        | orgId, actorUserId                               | audit                |
| `org.deleted`        | orgId, actorUserId                               | audit, alerting      |
| `member.invited`     | orgId, email(masked), inviteId, actorUserId      | send invite, audit   |
| `member.joined`      | orgId, userId                                    | audit                |
| `member.roles_changed` | orgId, userId, roleSlugs, actorUserId          | audit                |
| `member.removed`     | orgId, userId, actorUserId                        | audit                |
| `member.suspended`   | orgId, userId, actorUserId                        | audit                |
| `role.created` / `role.updated` / `role.deleted` | orgId, roleId, actorUserId | audit       |

---

## Listener wiring

```php
// Polaris ships these; hosts may add more.
bin/altair listeners:list --format=json          # inspect what's subscribed
bin/altair listeners:show auth.refresh_reuse_detected
```

- `AuditLogListener` → every event → `auth_audit_log` (append-only).
- `NotificationListener` → `user.registered`, `user.password_reset_requested`,
  `member.invited`, `user.locked`, `mfa.*` user-facing → mailer/SMS ports.
- Hosts add listeners (e.g. push `user.registered` to a CRM, alert on
  `auth.refresh_reuse_detected`) without touching Polaris.

> The notification *content/templates* are the host's concern via the
> `OtpMailerInterface` template name + context; Polaris defines the event and the
> data, not the copy.
