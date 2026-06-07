<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Auth;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\PayloadInterface;
use Univeros\Polaris\Token\ClientContext;

use function filter_var;
use function is_string;

use const FILTER_VALIDATE_EMAIL;

/**
 * Shared helpers for the auth HTTP domains: building responses and reading the client
 * context (IP) the request carries.
 */
abstract class AuthDomain implements DomainInterface
{
    /**
     * @param array<string, mixed> $output
     */
    protected function respond(int $status, array $output): PayloadInterface
    {
        return (new Payload())->withStatus($status)->withOutput($output);
    }

    /**
     * @param list<string> $errors
     */
    protected function unprocessable(array $errors): PayloadInterface
    {
        return $this->respond(422, ['errors' => $errors]);
    }

    protected function client(InputCollection $input): ClientContext
    {
        $ip = $input->get(MiddlewareInterface::ATTRIBUTE_IP_ADDRESS);

        return new ClientContext(is_string($ip) ? $ip : null);
    }

    protected function isEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
}
