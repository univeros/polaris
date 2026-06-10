<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Univeros\Polaris\Http\Auth\AcceptInviteDomain;
use Univeros\Polaris\Http\Auth\ChangePasswordDomain;
use Univeros\Polaris\Http\Auth\DeleteFactorDomain;
use Univeros\Polaris\Http\Auth\EmailEnrollDomain;
use Univeros\Polaris\Http\Auth\ForgotPasswordDomain;
use Univeros\Polaris\Http\Auth\LoginDomain;
use Univeros\Polaris\Http\Auth\LogoutAllDomain;
use Univeros\Polaris\Http\Auth\LogoutDomain;
use Univeros\Polaris\Http\Auth\MeDomain;
use Univeros\Polaris\Http\Auth\MfaChallengeDomain;
use Univeros\Polaris\Http\Auth\MfaFactorsDomain;
use Univeros\Polaris\Http\Auth\MfaVerifyDomain;
use Univeros\Polaris\Http\Auth\OtpFactorConfirmDomain;
use Univeros\Polaris\Http\Auth\RefreshTokenDomain;
use Univeros\Polaris\Http\Auth\RegenerateRecoveryCodesDomain;
use Univeros\Polaris\Http\Auth\RegisterDomain;
use Univeros\Polaris\Http\Auth\ResendVerificationDomain;
use Univeros\Polaris\Http\Auth\ResetPasswordDomain;
use Univeros\Polaris\Http\Auth\RevokeSessionDomain;
use Univeros\Polaris\Http\Auth\SessionsDomain;
use Univeros\Polaris\Http\Auth\SmsEnrollDomain;
use Univeros\Polaris\Http\Auth\StepUpChallengeDomain;
use Univeros\Polaris\Http\Auth\StepUpVerifyDomain;
use Univeros\Polaris\Http\Auth\SwitchOrgDomain;
use Univeros\Polaris\Http\Auth\TotpConfirmDomain;
use Univeros\Polaris\Http\Auth\TotpEnrollDomain;
use Univeros\Polaris\Http\Auth\UpdateFactorDomain;
use Univeros\Polaris\Http\Auth\VerifyEmailDomain;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Univeros\Polaris\Http\Orgs\ChangeMemberRolesDomain;
use Univeros\Polaris\Http\Orgs\ChangeMemberStatusDomain;
use Univeros\Polaris\Http\Orgs\CreateInviteDomain;
use Univeros\Polaris\Http\Orgs\CreateOrganizationDomain;
use Univeros\Polaris\Http\Orgs\CreateRoleDomain;
use Univeros\Polaris\Http\Orgs\DeleteOrganizationDomain;
use Univeros\Polaris\Http\Orgs\DeleteRoleDomain;
use Univeros\Polaris\Http\Orgs\ListInvitesDomain;
use Univeros\Polaris\Http\Orgs\ListMembersDomain;
use Univeros\Polaris\Http\Orgs\ListOrganizationsDomain;
use Univeros\Polaris\Http\Orgs\ListPermissionsDomain;
use Univeros\Polaris\Http\Orgs\ListRolesDomain;
use Univeros\Polaris\Http\Orgs\ReadOrganizationDomain;
use Univeros\Polaris\Http\Orgs\RemoveMemberDomain;
use Univeros\Polaris\Http\Orgs\RevokeInviteDomain;
use Univeros\Polaris\Http\Orgs\UpdateOrganizationDomain;
use Univeros\Polaris\Http\Orgs\UpdateRoleDomain;
use Univeros\Polaris\Http\Users\DeleteUserDomain;
use Univeros\Polaris\Http\Users\DisableUserDomain;
use Univeros\Polaris\Http\Users\EnableUserDomain;
use Univeros\Polaris\Http\Users\ReadUserDomain;
use Univeros\Polaris\Http\Users\UpdateUserDomain;

/**
 * The route table Polaris contributes to the host router.
 */
final class Routes
{
    /**
     * @return list<array{0: string, 1: string, 2: class-string}>
     */
    public static function table(): array
    {
        // See docs/auth/api-reference.md; more endpoints land in later Phase 1 issues.
        return [
            ['GET', '/auth/.well-known/jwks.json', JwksDomain::class],
            ['POST', '/auth/register', RegisterDomain::class],
            ['POST', '/auth/email/verify', VerifyEmailDomain::class],
            ['POST', '/auth/email/verify/resend', ResendVerificationDomain::class],
            ['POST', '/auth/login', LoginDomain::class],
            ['POST', '/auth/token/refresh', RefreshTokenDomain::class],
            ['POST', '/auth/logout', LogoutDomain::class],
            ['POST', '/auth/logout-all', LogoutAllDomain::class],
            ['POST', '/auth/switch-org', SwitchOrgDomain::class],
            ['GET', '/auth/sessions', SessionsDomain::class],
            ['DELETE', '/auth/sessions/{id}', RevokeSessionDomain::class],
            ['POST', '/auth/password/forgot', ForgotPasswordDomain::class],
            ['POST', '/auth/password/reset', ResetPasswordDomain::class],
            ['POST', '/auth/password/change', ChangePasswordDomain::class],
            ['GET', '/auth/me', MeDomain::class],
            ['POST', '/auth/mfa/totp/enroll', TotpEnrollDomain::class],
            ['POST', '/auth/mfa/totp/confirm', TotpConfirmDomain::class],
            ['POST', '/auth/mfa/sms/enroll', SmsEnrollDomain::class],
            ['POST', '/auth/mfa/sms/confirm', OtpFactorConfirmDomain::class],
            ['POST', '/auth/mfa/email/enroll', EmailEnrollDomain::class],
            ['POST', '/auth/mfa/email/confirm', OtpFactorConfirmDomain::class],
            ['POST', '/auth/mfa/challenge', MfaChallengeDomain::class],
            ['POST', '/auth/mfa/verify', MfaVerifyDomain::class],
            ['POST', '/auth/mfa/step-up/challenge', StepUpChallengeDomain::class],
            ['POST', '/auth/mfa/step-up', StepUpVerifyDomain::class],
            ['POST', '/auth/mfa/recovery-codes/regenerate', RegenerateRecoveryCodesDomain::class],
            ['GET', '/auth/mfa/factors', MfaFactorsDomain::class],
            ['PATCH', '/auth/mfa/factors/{id}', UpdateFactorDomain::class],
            ['DELETE', '/auth/mfa/factors/{id}', DeleteFactorDomain::class],
            ['POST', '/orgs', CreateOrganizationDomain::class],
            ['GET', '/orgs', ListOrganizationsDomain::class],
            ['GET', '/orgs/{id}', ReadOrganizationDomain::class],
            ['PATCH', '/orgs/{id}', UpdateOrganizationDomain::class],
            ['DELETE', '/orgs/{id}', DeleteOrganizationDomain::class],
            ['GET', '/orgs/{id}/members', ListMembersDomain::class],
            ['PATCH', '/orgs/{id}/members/{userId}/roles', ChangeMemberRolesDomain::class],
            ['PATCH', '/orgs/{id}/members/{userId}', ChangeMemberStatusDomain::class],
            ['DELETE', '/orgs/{id}/members/{userId}', RemoveMemberDomain::class],
            ['POST', '/orgs/{id}/invites', CreateInviteDomain::class],
            ['GET', '/orgs/{id}/invites', ListInvitesDomain::class],
            ['DELETE', '/orgs/{id}/invites/{inviteId}', RevokeInviteDomain::class],
            ['POST', '/auth/invites/accept', AcceptInviteDomain::class],
            ['GET', '/orgs/{id}/roles', ListRolesDomain::class],
            ['POST', '/orgs/{id}/roles', CreateRoleDomain::class],
            ['PATCH', '/orgs/{id}/roles/{roleId}', UpdateRoleDomain::class],
            ['DELETE', '/orgs/{id}/roles/{roleId}', DeleteRoleDomain::class],
            ['GET', '/permissions', ListPermissionsDomain::class],
            ['GET', '/users/{id}', ReadUserDomain::class],
            ['PATCH', '/users/{id}', UpdateUserDomain::class],
            ['POST', '/users/{id}/disable', DisableUserDomain::class],
            ['POST', '/users/{id}/enable', EnableUserDomain::class],
            ['DELETE', '/users/{id}', DeleteUserDomain::class],
        ];
    }
}
