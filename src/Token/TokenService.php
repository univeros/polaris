<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Persistence\Contracts\RepositoryInterface;
use Cycle\ORM\ORMInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\OrganizationSwitched;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\TokenRefreshed;
use Univeros\Polaris\Exception\InvalidGrantException;
use Univeros\Polaris\Exception\RefreshTokenReuseException;
use Univeros\Polaris\Security\Pepper;

use function base64_encode;
use function explode;
use function implode;
use function random_bytes;
use function rtrim;
use function strtr;

/**
 * Issues and refreshes sessions: a short-lived access JWT plus a rotating, opaque
 * refresh token.
 *
 * Refresh tokens rotate on every use — the presented token is revoked and a new one is
 * issued in the same `family_id`. Replaying an already-rotated token is the signature of
 * theft: the whole family is revoked, {@see RefreshReuseDetected} is emitted, and the
 * request is rejected. Only the HMAC hash of a refresh secret is stored
 * ({@see Pepper}); the plaintext is returned to the client exactly once.
 *
 * See `docs/auth/flows.md` §3 (issuance) and §5 (refresh & rotation).
 */
final class TokenService
{
    private const string PEPPER_CONTEXT = 'refresh';
    private const int SECRET_BYTES = 32; // 256-bit CSPRNG opaque secret

    /**
     * @param RepositoryInterface<RefreshToken> $refreshTokens
     */
    public function __construct(
        private readonly RepositoryInterface $refreshTokens,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly Pepper $pepper,
        private readonly TokenGeneratorInterface $accessTokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly AuthConfig $config,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
        private readonly ?ORMInterface $orm = null,
    ) {
    }

    /**
     * Open a new session: mint the first refresh token in a fresh family and an access
     * token bound to it. Used by the login flow after authentication succeeds.
     */
    public function issue(SessionPrincipal $principal, ClientContext $client): IssuedTokens
    {
        $now = $this->clock->now();
        $familyId = $this->uuid();
        $secret = $this->newSecret();
        $expiresAt = $now->add($this->seconds($this->config->refreshToken->ttl));

        $token = $this->newRefreshToken($principal->userId, $principal->organizationId, $familyId, null, $secret, $client, $expiresAt, $now);
        // Record how the user authenticated on the session row, so refreshes can restore it (#97).
        $token->mfa = $principal->mfa;
        $token->amr = implode(',', $principal->amr);
        $token->authTime = $principal->authTime;
        $this->unitOfWork->persist($token);
        $this->unitOfWork->flush();

        return new IssuedTokens(
            $this->mintAccess($principal, $familyId),
            $secret,
            $this->config->accessToken->ttl,
            $expiresAt,
            $familyId,
        );
    }

    /**
     * Mint a fresh access token for an **existing** session, stamping a new `auth_time` — the
     * step-up grant (issue #25). No refresh token is rotated or issued: the caller keeps its session
     * and only swaps its access token for one that records a recent strong authentication
     * (`amr=["pwd","otp"]`, `mfa=true`). The authorization context (roles/scope/org) is re-resolved.
     *
     * Step-up is the only path that mints an access token without presenting a refresh token, so —
     * like {@see refresh()} — it requires the session to still be live: if the family was revoked
     * (logout / logout-all), a still-valid access token must not be able to re-mint itself and
     * outlive the revocation.
     *
     * @throws InvalidGrantException the session has ended (no unrevoked token in the family)
     */
    public function stepUp(string $userId, ?string $organizationId, string $sessionId): string
    {
        $active = $this->refreshTokens->findOneBy(['familyId' => $sessionId, 'revokedAt' => null]);
        if (!$active instanceof RefreshToken) {
            throw new InvalidGrantException('The session is no longer active.');
        }

        $base = $this->principals->resolve($userId, $organizationId);

        $principal = new SessionPrincipal(
            userId: $base->userId,
            organizationId: $base->organizationId,
            roles: $base->roles,
            scope: $base->scope,
            emailVerified: $base->emailVerified,
            mfa: true,
            amr: ['pwd', 'otp'],
            authTime: $this->clock->now()->getTimestamp(),
        );

        // The strong authentication is a property of the session, not of the one access token
        // minted here: persist it so subsequent refreshes keep mfa/amr/auth_time (#97).
        $active->mfa = $principal->mfa;
        $active->amr = implode(',', $principal->amr);
        $active->authTime = $principal->authTime;
        $this->unitOfWork->persist($active);
        $this->unitOfWork->flush();

        return $this->mintAccess($principal, $sessionId);
    }

    /**
     * Re-scope an existing session to a different organization (issue #35). Mints a fresh access
     * token whose `org`/`roles`/`scope` reflect the new org, and re-points the live refresh token's
     * org context so subsequent refreshes stay scoped to it. Like {@see stepUp()} it mints without
     * rotating the refresh token, and — for the same reason — requires the session to still be live.
     * The caller must already have verified the user is an active member of the target org.
     *
     * @throws InvalidGrantException the session has ended (no unrevoked token in the family)
     */
    public function switchOrganization(string $userId, string $organizationId, string $sessionId): string
    {
        $active = $this->refreshTokens->findOneBy(['familyId' => $sessionId, 'revokedAt' => null]);
        if (!$active instanceof RefreshToken) {
            throw new InvalidGrantException('The session is no longer active.');
        }

        $fromOrganizationId = $active->organizationId;
        $active->organizationId = $organizationId;
        $this->unitOfWork->persist($active);
        $this->unitOfWork->flush();

        $principal = $this->withStoredAuthContext($this->principals->resolve($userId, $organizationId), $active);
        $accessToken = $this->mintAccess($principal, $sessionId);

        $this->events->dispatch(new OrganizationSwitched($userId, $fromOrganizationId, $organizationId));

        return $accessToken;
    }

    /**
     * Exchange a refresh token for a fresh pair, rotating it within its family.
     *
     * @throws RefreshTokenReuseException when an already-rotated token is replayed
     * @throws InvalidGrantException      when the token is unknown or expired
     */
    public function refresh(string $presentedSecret, ClientContext $client): IssuedTokens
    {
        $now = $this->clock->now();
        $current = $this->refreshTokens->findOneBy([
            'tokenHash' => $this->pepper->hash(self::PEPPER_CONTEXT, $presentedSecret),
        ]);

        if (!$current instanceof RefreshToken) {
            throw new InvalidGrantException('The refresh token is not recognized.');
        }

        if ($current->revokedAt !== null) {
            $this->onRevokedTokenPresented($current, $client, $now);
        }

        if ($current->expiresAt <= $now) {
            throw new InvalidGrantException('The refresh token has expired.');
        }

        $principal = $this->withStoredAuthContext(
            $this->principals->resolve($current->userId, $current->organizationId),
            $current,
        );

        // Without rotation the presented token stays valid; only a fresh access token is minted.
        if (!$this->config->refreshToken->rotation) {
            $current->lastUsedAt = $now;
            $this->unitOfWork->persist($current);
            $this->unitOfWork->flush();

            $this->events->dispatch(new TokenRefreshed($current->userId, $current->familyId));

            return new IssuedTokens(
                $this->mintAccess($principal, $current->familyId),
                $presentedSecret,
                $this->config->accessToken->ttl,
                $current->expiresAt,
                $current->familyId,
            );
        }

        // Atomic compare-and-swap on revoked_at: of two concurrent presentations of the same
        // secret, exactly one claims the rotation; the loser sees a just-rotated token and goes
        // down the replay path, firing reuse detection (the safe response to a genuine race).
        if (!$this->claimForRotation($current, $now)) {
            $current->revokedAt = $now;
            $current->revokedReason = RefreshToken::REASON_ROTATED;
            $this->onRevokedTokenPresented($current, $client, $now);
        }

        $current->lastUsedAt = $now;
        $current->revokedAt = $now;
        $current->revokedReason = RefreshToken::REASON_ROTATED;
        $this->unitOfWork->persist($current);

        $secret = $this->newSecret();
        $expiresAt = $this->nextExpiry($current, $now);
        $next = $this->newRefreshToken(
            $current->userId,
            $current->organizationId,
            $current->familyId,
            $current->id,
            $secret,
            new ClientContext($client->ip ?? $current->ip, $client->userAgent ?? $current->userAgent),
            $expiresAt,
            $now,
        );
        // The session's authentication context survives rotation unchanged (#97).
        $next->mfa = $current->mfa;
        $next->amr = $current->amr;
        $next->authTime = $current->authTime;
        $this->unitOfWork->persist($next);
        $this->unitOfWork->flush();

        $accessToken = $this->mintAccess($principal, $current->familyId);

        $this->events->dispatch(new TokenRefreshed($current->userId, $current->familyId));

        return new IssuedTokens($accessToken, $secret, $this->config->accessToken->ttl, $expiresAt, $current->familyId);
    }

    /**
     * Handle a presented token that is already revoked. Only a token consumed by *rotation*
     * being replayed is the stolen-token signature → revoke the whole family and alert.
     * A token revoked intentionally (logout, admin, password change) is just an ended
     * session and is rejected as a plain invalid grant — no family wipe, no theft alert.
     * Always throws.
     *
     * @throws RefreshTokenReuseException|InvalidGrantException
     */
    /**
     * Claim the token for rotation with a single conditional UPDATE; false means another
     * request rotated it first.
     */
    private function claimForRotation(RefreshToken $current, DateTimeImmutable $now): bool
    {
        if ($this->orm === null) {
            // In-memory test wiring has no database to CAS against; the entity-level
            // revoked check above already ran. Production wiring always passes the ORM.
            return true;
        }

        $source = $this->orm->getSource(RefreshToken::class);
        $affected = $source->getDatabase()->update(
            $source->getTable(),
            [
                'revoked_at' => $now,
                'revoked_reason' => RefreshToken::REASON_ROTATED,
                'last_used_at' => $now,
            ],
            ['id' => $current->id, 'revoked_at' => null],
        )->run();

        return $affected === 1;
    }

    private function onRevokedTokenPresented(RefreshToken $current, ClientContext $client, DateTimeImmutable $now): never
    {
        if ($this->config->refreshToken->reuseDetection && $current->revokedReason === RefreshToken::REASON_ROTATED) {
            $this->revokeFamily($current->familyId, RefreshToken::REASON_REUSE_DETECTED, $now);
            $this->events->dispatch(
                new RefreshReuseDetected($current->userId, $current->familyId, $client->ip, $client->userAgent),
            );

            throw new RefreshTokenReuseException('The refresh token has already been used.');
        }

        throw new InvalidGrantException('The refresh token is no longer valid.');
    }

    /**
     * Revoke every still-active token in a family (reuse detection, and reused by logout
     * flows). Already-revoked tokens are left untouched so their original reason stands.
     */
    public function revokeFamily(string $familyId, string $reason, ?DateTimeImmutable $at = null): void
    {
        $now = $at ?? $this->clock->now();

        foreach ($this->refreshTokens->findBy(['familyId' => $familyId]) as $token) {
            if ($token->revokedAt === null) {
                $token->revokedAt = $now;
                $token->revokedReason = $reason;
                $this->unitOfWork->persist($token);
            }
        }

        $this->unitOfWork->flush();
    }

    /**
     * Overlay the session's persisted authentication context onto a freshly resolved principal.
     * The resolver supplies *authorization* (roles/scope/email_verified), but how the user
     * authenticated — `mfa`/`amr`/`auth_time` — is a property of the session, recorded at
     * login and step-up; without this a refreshed token would read `mfa=false` after a
     * completed MFA login (issue #97). Pre-#97 rows have no stored `amr` and keep the
     * `['pwd']` default.
     */
    private function withStoredAuthContext(SessionPrincipal $resolved, RefreshToken $session): SessionPrincipal
    {
        return new SessionPrincipal(
            userId: $resolved->userId,
            organizationId: $resolved->organizationId,
            roles: $resolved->roles,
            scope: $resolved->scope,
            emailVerified: $resolved->emailVerified,
            mfa: $session->mfa,
            amr: $session->amr === null || $session->amr === '' ? ['pwd'] : explode(',', $session->amr),
            authTime: $session->authTime,
        );
    }

    private function mintAccess(SessionPrincipal $principal, string $sessionId): string
    {
        $claims = new AccessTokenClaims(
            subject: $principal->userId,
            jwtId: $this->uuid(),
            sessionId: $sessionId,
            organizationId: $principal->organizationId,
            roles: $principal->roles,
            scope: $principal->scope,
            emailVerified: $principal->emailVerified,
            mfa: $principal->mfa,
            amr: $principal->amr,
            // auth_time is the last *full* authentication time; it is not re-stamped on
            // refresh (a refresh is not a re-authentication). Omitted when unknown.
            authTime: $principal->authTime,
        );

        return $this->accessTokens->generate($claims->toClaims());
    }

    /**
     * The new token's expiry. Absolute by default (inherit the family's fixed expiry);
     * sliding mode extends to `now + ttl`, capped at `familyStart + max_lifetime`.
     */
    private function nextExpiry(RefreshToken $current, DateTimeImmutable $now): DateTimeImmutable
    {
        if (!$this->config->refreshToken->sliding) {
            return $current->expiresAt;
        }

        $candidate = $now->add($this->seconds($this->config->refreshToken->ttl));
        $cap = $this->familyStart($current)->add($this->seconds($this->config->refreshToken->maxLifetime));

        return $candidate < $cap ? $candidate : $cap;
    }

    private function familyStart(RefreshToken $current): DateTimeImmutable
    {
        // The family root (the login-issued token) has no parent and carries the start time.
        $root = $this->refreshTokens->findOneBy(['familyId' => $current->familyId, 'parentId' => null]);

        return $root instanceof RefreshToken ? $root->createdAt : $current->createdAt;
    }

    private function newRefreshToken(
        string $userId,
        ?string $organizationId,
        string $familyId,
        ?string $parentId,
        string $secret,
        ClientContext $client,
        DateTimeImmutable $expiresAt,
        DateTimeImmutable $now,
    ): RefreshToken {
        $token = new RefreshToken();
        $token->id = $this->uuid();
        $token->userId = $userId;
        $token->organizationId = $organizationId;
        $token->familyId = $familyId;
        $token->parentId = $parentId;
        $token->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $secret);
        $token->userAgent = $client->userAgent;
        $token->ip = $client->ip;
        $token->expiresAt = $expiresAt;
        $token->createdAt = $now;

        return $token;
    }

    private function newSecret(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(self::SECRET_BYTES)), '+/', '-_'), '=');
    }

    private function uuid(): string
    {
        return Uuid::v7()->toRfc4122();
    }

    private function seconds(int $seconds): DateInterval
    {
        return new DateInterval('PT' . $seconds . 'S');
    }
}
