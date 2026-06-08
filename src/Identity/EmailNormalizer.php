<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use function strtolower;
use function trim;

/**
 * Canonicalizes email addresses so the same address always maps to one stored value and
 * one lookup key. Kept in one place so registration and verification normalize identically.
 */
final class EmailNormalizer
{
    public static function normalize(string $email): string
    {
        return strtolower(trim($email));
    }
}
