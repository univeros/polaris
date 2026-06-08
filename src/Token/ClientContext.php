<?php

declare(strict_types=1);

namespace Univeros\Polaris\Token;

/**
 * The device/network context of a token request — recorded on the refresh-token row
 * (for the sessions list) and on reuse-detection events. Both fields are optional;
 * {@see none()} is the empty context for callers that have neither.
 */
final readonly class ClientContext
{
    public function __construct(
        public ?string $ip = null,
        public ?string $userAgent = null,
    ) {
    }

    public static function none(): self
    {
        return new self();
    }
}
