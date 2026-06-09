<?php

declare(strict_types=1);

namespace Univeros\Polaris\Http\Middleware;

/**
 * The authenticated principal carried by a validated `login_mfa` ticket: the id of the user who
 * cleared the password step. {@see MfaTokenMiddleware} attaches one as a request attribute the MFA
 * gate domains read.
 *
 * It is a typed object on purpose. Request attributes are merged into the domain's input alongside
 * the request body (body wins on a key clash), so a string attribute could be spoofed by a client
 * POSTing the attribute key. Requiring an `instanceof MfaTicket` — which a JSON body value can never
 * be — makes the trusted user id unforgeable, exactly as {@see \Altair\Http\Contracts\TokenInterface}
 * does for the access-token attribute.
 */
final readonly class MfaTicket
{
    /** Request-attribute key under which the validated ticket is attached. */
    public const string ATTRIBUTE = 'polaris:mfa:ticket';

    public function __construct(
        public string $userId,
    ) {
    }
}
