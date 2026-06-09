<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Univeros\Polaris\Entity\OtpChallenge;
use Univeros\Polaris\Event\MfaStepUpCompleted;
use Univeros\Polaris\Event\MfaVerifyFailed;
use Univeros\Polaris\Exception\InvalidOtpException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaChallengeVerifier;
use Univeros\Polaris\Mfa\OtpChallengeResult;
use Univeros\Polaris\Token\ClientContext;
use Univeros\Polaris\Token\TokenService;

/**
 * Step-up re-authentication (issue #25): re-verify a factor while already logged in to refresh the
 * session's `auth_time`, so a sensitive operation gated by {@see \Univeros\Polaris\Http\Middleware\StepUpMiddleware}
 * can proceed.
 *
 * It reuses the shared {@see MfaChallengeVerifier} (purpose `step_up`) for the factor routing and on
 * success mints a **fresh access token for the existing session** ({@see TokenService::stepUp}) — no
 * new session, no refresh rotation; the client swaps its access token and retries. Emits
 * `mfa.step_up_completed`; failures emit the shared `mfa.verify_failed`.
 */
final readonly class StepUpService
{
    public function __construct(
        private MfaChallengeVerifier $verifier,
        private TokenService $tokens,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * Issue and send a `step_up` OTP for an sms/email factor, returning its masked destination.
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the factor type does not use a sent challenge, or a cooldown
     */
    public function challenge(string $userId, string $factorId, ClientContext $client): OtpChallengeResult
    {
        return $this->verifier->challenge($userId, $factorId, OtpChallenge::PURPOSE_STEP_UP, $client);
    }

    /**
     * Verify the code (or recovery code) and, on success, return a refreshed access token for the
     * caller's existing session.
     *
     * @throws MfaFactorNotFoundException the factor is unknown, unconfirmed, or another user's
     * @throws InvalidOtpException        the code is wrong, expired, exhausted, or already used
     */
    public function verify(
        string $userId,
        ?string $organizationId,
        string $sessionId,
        ?string $factorId,
        #[SensitiveParameter] string $code,
    ): string {
        try {
            $this->verifier->verify($userId, $factorId, $code, OtpChallenge::PURPOSE_STEP_UP);
        } catch (InvalidOtpException | MfaFactorNotFoundException $failure) {
            $this->events->dispatch(new MfaVerifyFailed($userId));

            throw $failure;
        }

        $accessToken = $this->tokens->stepUp($userId, $organizationId, $sessionId);
        $this->events->dispatch(new MfaStepUpCompleted($userId, $sessionId));

        return $accessToken;
    }
}
