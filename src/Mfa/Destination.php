<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Univeros\Polaris\Entity\OtpChallenge;

use function str_contains;
use function strrpos;
use function substr;
use function trim;

/**
 * Masks an OTP destination (phone / email) for safe display in responses — enough to recognise
 * "which device", never enough to reveal the full contact (privacy, spec §5).
 */
final class Destination
{
    public static function mask(string $channel, string $destination): string
    {
        if ($destination === '') {
            return '';
        }

        return $channel === OtpChallenge::CHANNEL_EMAIL
            ? self::maskEmail($destination)
            : self::maskPhone($destination);
    }

    private static function maskEmail(string $email): string
    {
        $at = strrpos($email, '@');
        if ($at === false || $at === 0) {
            return '***';
        }

        return $email[0] . '***' . substr($email, $at);
    }

    private static function maskPhone(string $phone): string
    {
        // Keep a short leading hint and the last four; mask the middle.
        $last4 = substr($phone, -4);
        $prefix = str_contains($phone, '+') ? substr($phone, 0, 2) : '';

        return trim($prefix . ' *** *** ' . $last4);
    }
}
