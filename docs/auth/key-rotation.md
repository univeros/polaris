# Key Rotation Runbook (JWKS `kid` rotation)

Operational procedure for rotating the JWT signing keypair with zero downtime.
Audience: the operator running a Polaris host. Time required: two short config
changes separated by one access-token TTL window (15 minutes by default).

The design in one line: publish the new public key alongside the old one,
switch signing to the new key, then retire the old key once every token signed
with it has expired.

---

## 1. Background

- Access tokens are asymmetric JWTs. The private key
  (`AUTH_JWT_PRIVATE_KEY`) signs; the public key (`AUTH_JWT_PUBLIC_KEY`)
  verifies. Each key is identified by a `kid` (`AUTH_JWT_KID`, defaulting to a
  hash of the public key).
- `GET /auth/.well-known/jwks.json` publishes the public key(s) as a JWK Set.
  Resource servers select the verification key by the token's `kid` header.
- During a rotation the retiring public key stays published via
  `AUTH_JWT_PREVIOUS_PUBLIC_KEY` (and optional `AUTH_JWT_PREVIOUS_KID`), so
  tokens signed before the switch keep verifying until they expire.
- Refresh tokens are opaque secrets, not JWTs: rotation never invalidates
  sessions. A client whose access token is rejected simply refreshes and
  receives a token signed with the new key.

## 2. Preconditions

- [ ] A new RSA keypair, generated outside the repository and stored in the
  secret manager:
  `openssl genrsa -out new-private.pem 2048 && openssl rsa -in new-private.pem -pubout -out new-public.pem`
- [ ] The current `AUTH_JWT_PUBLIC_KEY` value at hand (it becomes the
  "previous" key during the overlap).
- [ ] Access-token TTL known (`auth.access_token.ttl`, default 900 seconds).

## 3. Procedure

### Step 1: publish both keys, switch signing

Update the environment (or secret manager) in a single deploy:

| Variable                       | New value                              |
| ------------------------------ | -------------------------------------- |
| `AUTH_JWT_PRIVATE_KEY`         | the new private key                    |
| `AUTH_JWT_PUBLIC_KEY`          | the new public key                     |
| `AUTH_JWT_KID`                 | a new id (or unset to derive from key) |
| `AUTH_JWT_PREVIOUS_PUBLIC_KEY` | the old public key                     |
| `AUTH_JWT_PREVIOUS_KID`        | the old kid (or unset to derive)       |

Effects, immediately after the deploy:

- New access tokens are signed with the new key and carry the new `kid`.
- The JWKS lists both keys; resource servers that refresh it verify both
  generations.
- The auth service itself validates with the active public key only, so a
  not-yet-expired token from before the switch is rejected locally with `401`.
  Clients recover transparently: the `401` triggers a refresh, which issues a
  token signed with the new key. Sessions are unaffected.

Verify:

```bash
curl -s https://auth.example.com/auth/.well-known/jwks.json | jq '.keys[].kid'
# expect two kids: the new one and the previous one
```

Log in (or refresh) and confirm the token header carries the new `kid`:

```bash
curl -s -X POST .../auth/token/refresh -d '{"refresh_token": "..."}' \
  | jq -r '.data.access_token' | cut -d. -f1 | base64 -d | jq .kid
```

### Step 2: retire the old key (after one access-TTL window)

Wait at least `auth.access_token.ttl` (default 15 minutes) after Step 1, so
every token signed with the old key has expired. Then remove:

| Variable                       | New value |
| ------------------------------ | --------- |
| `AUTH_JWT_PREVIOUS_PUBLIC_KEY` | unset     |
| `AUTH_JWT_PREVIOUS_KID`        | unset     |

Verify the JWKS now lists a single `kid`. Destroy the old private key in the
secret manager; it must never be needed again.

### Rollback

Any time before Step 2: redeploy with the old values in
`AUTH_JWT_PRIVATE_KEY` / `AUTH_JWT_PUBLIC_KEY` / `AUTH_JWT_KID` and the new
public key in the `PREVIOUS` slots (the mirror image of Step 1). Tokens issued
during the attempt then age out within one TTL window.

## 4. Cadence and triggers

- Routine rotation: per host policy (quarterly is a common choice).
- Immediate rotation: on any suspicion of private-key exposure. In that case
  ALSO revoke sessions (`logout-everywhere` tooling or
  `SessionService::revokeAll`) and skip the overlap: do not publish the
  compromised key as `PREVIOUS`; accept the forced re-login.

## 5. Related secrets

- **`APP_KEY` (pepper/HKDF seed):** rotating it invalidates every stored
  HMAC (refresh tokens, OTP codes, recovery codes, invite/reset/verify
  tokens) and the TOTP secret encryption. Treat it as a break-glass rotation:
  schedule it, expect all sessions and outstanding tokens to die, and
  regenerate recovery codes afterwards. There is no overlap mechanism.
- Database credentials, SMTP/SMS provider keys: host concern, no Polaris
  involvement.

See `docs/auth/security.md` section 2 for the design rationale.
