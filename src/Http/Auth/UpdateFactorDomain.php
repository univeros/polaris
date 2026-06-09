<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Exception\InvalidMfaFactorStateException;
use Univeros\Polaris\Exception\MfaFactorNotFoundException;
use Univeros\Polaris\Identity\MfaFactorView;
use Univeros\Polaris\Mfa\MfaManagementService;

use function trim;

/**
 * `PATCH /auth/mfa/factors/{id} {label?, default?}` — relabel a factor and/or make it the default
 * (spec §8). An omitted `label` is left unchanged; an empty `label` clears it. Only a confirmed
 * factor may be made the default.
 */
final class UpdateFactorDomain extends AuthDomain
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

        // hasKey distinguishes "label omitted" (leave it) from "label cleared" (empty string).
        $label = $input->hasKey('label') ? (string) $input->get('label') : null;
        $makeDefault = (bool) $input->get('default', false);

        try {
            $factor = $this->service->update($userId, $factorId, $label, $makeDefault);
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (InvalidMfaFactorStateException $exception) {
            return $this->respond(422, ['error' => 'invalid_state', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => MfaFactorView::of($factor)->toManagementArray()]);
    }
}
