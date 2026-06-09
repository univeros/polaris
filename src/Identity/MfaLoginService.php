<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Persistence\Contracts\RepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Event\MfaVerified;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaTotpService;
use Univeros\Polaris\Mfa\OtpChallengeResult;
use Univeros\Polaris\Mfa\OtpService;
use Univeros\Polaris\Mfa\RecoveryCodeService;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\IssuedTokens;
use Univeros\Polaris\Token\MfaLoginTokenService;
use Univeros\Polaris\Token\SessionPrincipal;
use Univeros\Polaris\Token\SessionPrincipalResolverInterface;
use Univeros\Polaris\Token\TokenService;

use function array_map;
use function in_array;

/**
 * The second step of an MFA login: it lists a user's confirmed factors, issues per-channel
 * challenges, and verifies a submitted code (or recovery code) — minting the **real** session only
 * once a factor is satisfied.
 *
 * Verification dispatches by factor type to the channel that owns it ({@see MfaTotpService} for
 * TOTP, {@see OtpService} for sms/email under the `login_mfa` purpose, {@see RecoveryCodeService}
 * for a recovery code when no factor is named). On success the minted access token records a full
 * second-factor authentication (`amr=["pwd","otp"]`, `mfa=true`, a fresh `auth_time`) and
 * `mfa.verified` + `user.logged_in` are emitted; every failure emits `mfa.verify_failed`.
 *
 * @see LoginService the password step that returns an {@see MfaChallengeResult} pointing here
 */
final readonly class MfaLoginService
{
    /**
     * @param RepositoryInterface<MfaFactor> $factors
     */
    public function __construct(
        private RepositoryInterface $factors,
        private MfaTotpService $totp,
        private OtpService $otp,
        private RecoveryCodeService $recovery,
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
     * @return list<MfaFactor>
     */
    public function confirmedFactors(string $userId): array
    {
        $confirmed = [];
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            if ($factor->confirmedAt !== null) {
                $confirmed[] = $factor;
            }
        }

        return $confirmed;
    }

    /**
     * Build the MFA-required login outcome: a short-lived `login_mfa` ticket plus the masked views
     * of the factors the client may use to complete the second step.
     *
     * @param list<MfaFactor> $confirmedFactors
     */
    public function beginChallenge(string $userId, array $confirmedFactors): MfaChallengeResult
    {
        $views = array_map(MfaFactorView::of(...), $confirmedFactors);

        return new MfaChallengeResult($userId, $this->tickets->issue($userId), $views);
    }

    /**
     * Issue and send a `login_mfa` OTP for an sms/email factor, returning its masked destination.
     * TOTP and recovery codes have no server-sent code, so they are rejected here.
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the factor type does not use a sent challenge, or a cooldown
     */
    public function challenge(string $userId, string $factorId, ClientContext $client): OtpChallengeResult
    {
        $factor = $this->requireConfirmedFactor($userId, $factorId);
        if (!in_array($factor->type, [MfaFactor::TYPE_SMS, MfaFactor::TYPE_EMAIL], true)) {
            throw new InvalidOtpException('This factor does not require a challenge.');
        }

        return $this->otp->challenge($userId, $factor, OtpChallenge::PURPOSE_LOGIN_MFA, $client);
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
            $verifiedFactorId = $this->dispatchVerify($userId, $factorId, $code);
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
     * Route the code to the verifier that owns the factor type, returning the factor id that cleared
     * the gate (null for the recovery-code path, which names no factor).
     *
     * @throws MfaFactorNotFoundException|InvalidOtpException
     */
    private function dispatchVerify(string $userId, ?string $factorId, #[SensitiveParameter] string $code): ?string
    {
        // No factor named → a recovery code stands in for an OTP (spec §6).
        if ($factorId === null || $factorId === '') {
            if (!$this->recovery->verify($userId, $code)) {
                throw new InvalidOtpException('The verification code is invalid.');
            }

            return null;
        }

        $factor = $this->requireConfirmedFactor($userId, $factorId);
        match ($factor->type) {
            MfaFactor::TYPE_TOTP => $this->totp->verify($userId, $factorId, $code),
            MfaFactor::TYPE_SMS,
            MfaFactor::TYPE_EMAIL => $this->otp->verify($userId, $factorId, $code, OtpChallenge::PURPOSE_LOGIN_MFA),
            default => throw new MfaFactorNotFoundException('MFA factor not found.'),
        };

        return $factorId;
    }

    /**
     * @throws MfaFactorNotFoundException
     */
    private function requireConfirmedFactor(string $userId, string $factorId): MfaFactor
    {
        $factor = $this->factors->find($factorId);
        if (!$factor instanceof MfaFactor || $factor->userId !== $userId || $factor->confirmedAt === null) {
            throw new MfaFactorNotFoundException('MFA factor not found.');
        }

        return $factor;
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
