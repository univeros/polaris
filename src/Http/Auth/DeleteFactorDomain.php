<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\LastFactorProtectedException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Mfa\MfaManagementService;

use function trim;

/**
 * `DELETE /auth/mfa/factors/{id}` — remove one of the authenticated user's factors (spec §8).
 * Step-up gated (enforced by {@see \Univeros\Polaris\Http\Middleware\StepUpMiddleware}); removing the
 * last confirmed factor is blocked while MFA is enforced for the user (`409`).
 */
final class DeleteFactorDomain extends AuthDomain
{
    public function __construct(private readonly MfaManagementService $service)
    {
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '') {
            return $this->unauthorized();
        }

        $factorId = trim((string) $input->get('id', ''));
        if ($factorId === '') {
            return $this->unprocessable(['A factor id is required.']);
        }

        try {
            $this->service->remove($userId, $factorId);
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (LastFactorProtectedException $exception) {
            return $this->respond(409, ['error' => 'last_factor_protected', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['status' => 'removed']]);
    }
}
