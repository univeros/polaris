<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Orgs;

use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Override;
use Univeros\Polaris\Authorization\OrganizationService;

/**
 * `GET /orgs` — the organizations the authenticated caller is an active member of.
 */
final class ListOrganizationsDomain extends OrganizationDomain
{
    public function __construct(private readonly OrganizationService $organizations)
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

        $data = [];
        foreach ($this->organizations->listForUser($userId) as $organization) {
            $data[] = [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
            ];
        }

        return $this->respond(200, ['data' => $data]);
    }
}
