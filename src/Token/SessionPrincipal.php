<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

/**
 * The authenticated identity and its session context, used to build the access-token
 * claim set ({@see AccessTokenClaims}) — everything except the session-specific `jti`
 * and `sid`, which {@see TokenService} owns.
 *
 * `roles`/`scope`/`organizationId` are the authorization context (re-resolved each
 * issue/refresh); `emailVerified`/`mfa`/`amr`/`authTime` describe how the user
 * authenticated.
 */
final readonly class SessionPrincipal
{
    /**
     * @param list<string> $roles
     * @param list<string> $scope
     * @param list<string> $amr
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId = null,
        public array $roles = [],
        public array $scope = [],
        public bool $emailVerified = false,
        public bool $mfa = false,
        public array $amr = ['pwd'],
        public ?int $authTime = null,
    ) {
    }
}
