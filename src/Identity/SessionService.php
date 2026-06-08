<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Univeros\Polaris\Entity\RefreshToken;
use Univeros\Polaris\Event\SessionsRevoked;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\TokenService;

use function array_keys;

use const DATE_ATOM;

/**
 * Manages a user's sessions (refresh-token families): listing active devices, logging out
 * the current session, logging out everywhere, and revoking a specific session.
 *
 * A session is a refresh `family_id`; rotation keeps exactly one active token per family,
 * so "active sessions" are the families with a non-revoked, unexpired token. Revocation
 * delegates to {@see TokenService::revokeFamily()} (the same path reuse detection uses).
 *
 * See `docs/auth/flows.md` §7.
 */
final class SessionService
{
    /**
     * @param RepositoryInterface<RefreshToken> $refreshTokens
     */
    public function __construct(
        private readonly RepositoryInterface $refreshTokens,
        private readonly TokenService $tokens,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Active sessions for a user, newest device first is not guaranteed; each entry flags
     * whether it is the calling session (matched by `sid`).
     *
     * @return list<array<string, mixed>>
     */
    public function listFor(string $userId, string $currentSessionId): array
    {
        $now = $this->clock->now();

        /** @var array<string, array{root: RefreshToken, active: RefreshToken|null}> $families */
        $families = [];
        foreach ($this->refreshTokens->findBy(['userId' => $userId]) as $token) {
            $family = $families[$token->familyId] ?? ['root' => $token, 'active' => null];
            if ($token->parentId === null) {
                $family['root'] = $token;
            }
            if ($token->revokedAt === null && $token->expiresAt > $now) {
                $family['active'] = $token;
            }
            $families[$token->familyId] = $family;
        }

        $sessions = [];
        foreach ($families as $familyId => $family) {
            $active = $family['active'];
            if ($active === null) {
                continue;
            }

            $sessions[] = [
                'id' => $familyId,
                'current' => $familyId === $currentSessionId,
                'ip' => $active->ip,
                'user_agent' => $active->userAgent,
                'created_at' => $family['root']->createdAt->format(DATE_ATOM),
                'last_used_at' => ($active->lastUsedAt ?? $active->createdAt)->format(DATE_ATOM),
            ];
        }

        return $sessions;
    }

    /**
     * Revoke the caller's current session (the `sid` from its access token).
     */
    public function logout(string $sessionId): void
    {
        $this->tokens->revokeFamily($sessionId, RefreshToken::REASON_LOGOUT);
    }

    /**
     * Revoke every session for the user (logout everywhere).
     */
    public function logoutAll(string $userId, ClientContext $client): void
    {
        $families = [];
        foreach ($this->refreshTokens->findBy(['userId' => $userId]) as $token) {
            $families[$token->familyId] = true;
        }

        foreach (array_keys($families) as $familyId) {
            $this->tokens->revokeFamily($familyId, RefreshToken::REASON_LOGOUT);
        }

        $this->events->dispatch(new SessionsRevoked($userId, $client->ip));
    }

    /**
     * Revoke a specific session, but only if it belongs to the user. Returns false when no
     * such session exists for them (mapped to a 404 — no cross-user disclosure).
     */
    public function revoke(string $userId, string $sessionId): bool
    {
        $owned = false;
        foreach ($this->refreshTokens->findBy(['familyId' => $sessionId]) as $token) {
            if ($token->userId === $userId) {
                $owned = true;
                break;
            }
        }

        if (!$owned) {
            return false;
        }

        $this->tokens->revokeFamily($sessionId, RefreshToken::REASON_LOGOUT);

        return true;
    }
}
