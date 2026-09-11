<?php

declare(strict_types=1);

namespace App\Account;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\TokenInterface;
use Polaris\Model\User;
use Polaris\Wiring\Graph;

/**
 * `GET /app/me`: the application's own protected endpoint. The token the framework's
 * authentication middleware attached (a Polaris access token, through the module's bridge) is in
 * the input under `TokenInterface::TOKEN_KEY`; the user comes from Polaris's repositories.
 */
final class Me
{
    public function __construct(private readonly Graph $graph)
    {
    }

    public function __invoke(InputCollection $input): PayloadInterface
    {
        $token = $input->get(TokenInterface::TOKEN_KEY);
        $userId = $token instanceof TokenInterface ? (string) $token->getMetadata('sub') : '';
        $user = $userId === '' ? null : $this->graph->users()->find($userId);
        if (!$user instanceof User) {
            return (new Payload())->withStatus(401)->withOutput(['error' => 'unauthorized', 'message' => 'Authentication is required.']);
        }

        return (new Payload())->withStatus(200)->withOutput(['data' => [
            'id' => $user->id,
            'email' => $user->email,
            'organization_id' => $token->getMetadata('org'),
            'roles' => $token->getMetadata('roles') ?? [],
        ]]);
    }
}
