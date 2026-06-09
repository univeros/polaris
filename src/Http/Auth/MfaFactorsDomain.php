<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Identity\MfaFactorView;
use Univeros\Polaris\Mfa\MfaManagementService;

use function array_map;

/**
 * `GET /auth/mfa/factors` — list the authenticated user's MFA factors (type, label, masked
 * destination, confirmed, default), including still-pending ones (spec §8).
 */
final class MfaFactorsDomain extends AuthDomain
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

        $factors = array_map(
            static fn(MfaFactor $factor): array => MfaFactorView::of($factor)->toManagementArray(),
            $this->service->list($userId),
        );

        return $this->respond(200, ['data' => ['factors' => $factors]]);
    }
}
