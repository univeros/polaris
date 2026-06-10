<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

/**
 * The purposes an OTP challenge may be scoped to (`auth_otp_challenges.purpose`).
 *
 * Purpose isolation keeps a code issued for one flow from satisfying another — an `enroll`
 * code cannot clear the `login_mfa` gate, a `login_mfa` code cannot satisfy `step_up`, and so
 * on. The enum makes that isolation a type-level guarantee: every {@see OtpService} and
 * {@see MfaChallengeVerifier} entry point takes a case, so a caller cannot pass a stray or
 * misspelled string (issue #97). The backing value is what the column stores.
 */
enum ChallengePurpose: string
{
    /** The 2FA step of the login flow. */
    case LoginMfa = 'login_mfa';

    /** Confirming a new sms/email factor at enrollment. */
    case Enroll = 'enroll';

    /** OTP-style password-reset delivery. */
    case PasswordReset = 'password_reset';

    /** OTP-style email-verification delivery. */
    case EmailVerify = 'email_verify';

    /** Step-up re-authentication within an existing session. */
    case StepUp = 'step_up';
}
