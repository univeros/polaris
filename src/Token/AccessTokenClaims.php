<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

use InvalidArgumentException;

/**
 * The Polaris access-token claim set as an immutable value object.
 *
 * It models the application-level claims (subject, session, org/roles, MFA/AMR,
 * auth-time) and renders them to the flat array {@see PolarisTokenGenerator} mints.
 * The protocol claims (`iss`, `aud`, `iat`, `exp`, `nbf`) are owned by the generator
 * and the token configuration, so they are intentionally absent here.
 *
 * See `docs/auth/flows.md` §6 for the claim reference.
 */
final readonly class AccessTokenClaims
{
    /**
     * @param string           $subject  user id (`sub`); must not be empty
     * @param string           $jwtId    unique token id (`jti`); must not be empty
     * @param list<string>     $roles    role slugs in the active org
     * @param list<string>     $scope    flattened permission keys (off by default)
     * @param list<string>     $amr      authentication methods, e.g. `["pwd","otp"]`
     */
    public function __construct(
        public string $subject,
        public string $jwtId,
        public ?string $sessionId = null,
        public ?string $organizationId = null,
        public array $roles = [],
        public array $scope = [],
        public bool $emailVerified = false,
        public bool $mfa = false,
        public array $amr = [],
        public ?int $authTime = null,
    ) {
        if ($subject === '') {
            throw new InvalidArgumentException('Access-token subject (sub) must not be empty.');
        }

        if ($jwtId === '') {
            throw new InvalidArgumentException('Access-token id (jti) must not be empty.');
        }
    }

    /**
     * The claims as a flat map for the generator. `org` is always present (nullable by
     * design) so resource servers can distinguish "no active org" from a missing claim;
     * `sid`, `scope`, and `auth_time` are emitted only when set.
     *
     * @return array<string, mixed>
     */
    public function toClaims(): array
    {
        $claims = [
            'sub' => $this->subject,
            'jti' => $this->jwtId,
            'org' => $this->organizationId,
            'roles' => $this->roles,
            'email_verified' => $this->emailVerified,
            'mfa' => $this->mfa,
            'amr' => $this->amr,
        ];

        if ($this->sessionId !== null) {
            $claims['sid'] = $this->sessionId;
        }

        if ($this->scope !== []) {
            $claims['scope'] = $this->scope;
        }

        if ($this->authTime !== null) {
            $claims['auth_time'] = $this->authTime;
        }

        return $claims;
    }
}
