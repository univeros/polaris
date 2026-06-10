<?php

declare(strict_types=1);

namespace Univeros\Polaris\Security;

use SensitiveParameter;
use Univeros\Polaris\Exception\InvalidConfigException;

use function ctype_xdigit;
use function hash_equals;
use function hash_hkdf;
use function hash_hmac;
use function strlen;

/**
 * Keyed hashing for secrets that must be verifiable but never recoverable —
 * refresh tokens, OTP codes, recovery codes, and reset/verification tokens.
 *
 * A per-context key is derived from the application key with HKDF (so the
 * `refresh`, `otp`, and `recovery` contexts use independent keys), then values
 * are HMACed under it. Comparison is constant-time. Plaintext is never stored.
 */
final class Pepper
{
    /** HKDF input keying material must carry the full 256 bits of the derived keys' strength. */
    public const int MIN_KEY_BYTES = 32;

    private const ALGO = 'sha256';
    private const INFO_PREFIX = 'polaris:pepper:';

    public function __construct(#[SensitiveParameter] private readonly string $appKey)
    {
        if (strlen($appKey) < self::MIN_KEY_BYTES) {
            throw new InvalidConfigException(
                'Pepper requires an application key of at least ' . self::MIN_KEY_BYTES . ' bytes.',
            );
        }
    }

    /**
     * Keyed HMAC of $value for the given context, as a lowercase hex digest.
     */
    public function hash(string $context, #[SensitiveParameter] string $value): string
    {
        $key = hash_hkdf(self::ALGO, $this->appKey, 32, self::INFO_PREFIX . $context);

        return hash_hmac(self::ALGO, $value, $key);
    }

    /**
     * Constant-time comparison of $value (re-hashed for $context) against a stored hash.
     */
    public function matches(string $context, #[SensitiveParameter] string $value, string $hash): bool
    {
        if ($hash === '' || !ctype_xdigit($hash)) {
            return false;
        }

        return hash_equals($this->hash($context, $value), $hash);
    }
}
