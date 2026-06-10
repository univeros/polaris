<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Univeros\Polaris\Mfa\ChallengePurpose;
use Univeros\Polaris\Event\MfaVerified;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;
use Univeros\Polaris\Mfa\OtpChallengeResult;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\IssuedTokens;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

use function array_map;

/**
 * The second step of an MFA login: it lists a user's confirmed factors, issues per-channel
 * challenges, and verifies a submitted code (or recovery code) — minting the **real** session only
 * once a factor is satisfied.
 *
 * The factor routing and replay rules live in {@see MfaChallengeVerifier} (shared with step-up); this
 * service wraps it with the login policy — on success the minted access token records a full
 * second-factor authentication (`amr=["pwd","otp"]`, `mfa=true`, a fresh `auth_time`) and
 * `mfa.verified` + `user.logged_in` are emitted; every failure emits `mfa.verify_failed`.
 *
 * @see LoginService the password step that returns an {@see MfaChallengeResult} pointing here
 */
final readonly class MfaLoginService
{
    public function __construct(
        private MfaChallengeVerifier $verifier,
        private MfaLoginTokenService $tickets,
        private TokenService $tokens,
        private SessionPrincipalResolverInterface $principals,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * The user's confirmed factors — the only ones that can satisfy the gate.
     *
     * @return list<\Univeros\Polaris\Entity\MfaFactor>
     */
    public function confirmedFactors(string $userId): array
    {
        return $this->verifier->confirmedFactors($userId);
    }

    /**
     * Build the MFA-required login outcome: a short-lived `login_mfa` ticket plus the masked views
     * of the factors the client may use to complete the second step.
     *
     * @param list<\Univeros\Polaris\Entity\MfaFactor> $confirmedFactors
     */
    public function beginChallenge(string $userId, array $confirmedFactors): MfaChallengeResult
    {
        $views = array_map(MfaFactorView::of(...), $confirmedFactors);

        return new MfaChallengeResult($userId, $this->tickets->issue($userId), $views);
    }

    /**
     * Issue and send a `login_mfa` OTP for an sms/email factor, returning its masked destination.
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the factor type does not use a sent challenge, or a cooldown
     */
    public function challenge(string $userId, string $factorId, ClientContext $client): OtpChallengeResult
    {
        return $this->verifier->challenge($userId, $factorId, ChallengePurpose::LoginMfa, $client);
    }

    /**
     * Verify the submitted code against the named factor — or, when no factor is named, against the
     * user's recovery codes — and, on success, mint the real token pair.
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the code is wrong, expired, exhausted, or already used
     */
    public function verify(
        string $userId,
        ?string $factorId,
        #[SensitiveParameter] string $code,
        ClientContext $client,
    ): IssuedTokens {
        try {
            $verifiedFactorId = $this->verifier->verify($userId, $factorId, $code, ChallengePurpose::LoginMfa);
        } catch (InvalidOtpException | MfaFactorNotFoundException $failure) {
            $this->events->dispatch(new MfaVerifyFailed($userId));

            throw $failure;
        }

        $tokens = $this->mint($userId, $client);
        $this->events->dispatch(new MfaVerified($userId, $verifiedFactorId));
        $this->events->dispatch(new UserLoggedIn($userId, $tokens->sessionId, $client->ip));

        return $tokens;
    }

    /**
     * Mint the post-MFA session: the access token records a full second-factor authentication
     * (`amr=["pwd","otp"]`, `mfa=true`, fresh `auth_time`) over the resolved authorization context.
     */
    private function mint(string $userId, ClientContext $client): IssuedTokens
    {
        $base = $this->principals->resolve($userId, null);

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

        return $this->tokens->issue($principal, $client);
    }
}
