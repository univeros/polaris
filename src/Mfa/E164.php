<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use function preg_match;

/**
 * Validates a phone number against the E.164 format: a leading `+`, a non-zero first digit, and a
 * total of 7–15 digits (e.g. `+14155550101`). 7 is the practical ITU-T minimum, so format-only
 * junk like `+12` is rejected before a provider would. The SMS enroll endpoint rejects anything
 * else `422`.
 */
final class E164
{
    public static function isValid(string $phone): bool
    {
        return preg_match('/^\+[1-9]\d{5,14}$/', $phone) === 1;
    }
}
