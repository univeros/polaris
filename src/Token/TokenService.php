<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use Altair\Http\Contracts\TokenGeneratorInterface;
use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Config\AuthConfig;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\TokenRefreshed;
use Univeros\Polaris\Exception\InvalidGrantException;
use Univeros\Polaris\Exception\RefreshTokenReuseException;
use Univeros\Polaris\Security\Pepper;

use function base64_encode;
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
     * Exchange a refresh token for a fresh pair, rotating it within its family.
     *
     * @throws RefreshTokenReuseException when an already-rotated token is replayed
     * @throws InvalidGrantException      when the token is unknown or expired
     */
    public function refresh(string $presentedSecret, ClientContext $client): IssuedTokens
    {
        $now = $this->clock->now();
        // Note: this read-check-write is not row-locked, so two concurrent refreshes of
        // the *same* token could both rotate. Strict single-use under concurrency needs a
        // SELECT ... FOR UPDATE around the lookup; tracked as a hardening follow-up.
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

        $principal = $this->principals->resolve($current->userId, $current->organizationId);

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
        $this->unitOfWork->persist($next);
        $this->unitOfWork->flush();

        $accessToken = $this->mintAccess($principal, $current->familyId);

        $this->events->dispatch(new TokenRefreshed($current->userId, $current->familyId));

        return new IssuedTokens($accessToken, $secret, $this->config->accessToken->ttl, $expiresAt, $current->familyId);
    }

    /**
     * Handle a presented token that is already revoked. With reuse detection on (default),
     * this is a stolen-token replay: revoke the whole family and alert. With it off, the
     * token is simply rejected as an invalid grant. Always throws.
     *
     * @throws RefreshTokenReuseException|InvalidGrantException
     */
    private function onRevokedTokenPresented(RefreshToken $current, ClientContext $client, DateTimeImmutable $now): never
    {
        if ($this->config->refreshToken->reuseDetection) {
            $this->revokeFamily($current->familyId, RefreshToken::REASON_REUSE_DETECTED, $now);
            $this->events->dispatch(new RefreshReuseDetected($current->userId, $current->familyId, $client->ip));

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
