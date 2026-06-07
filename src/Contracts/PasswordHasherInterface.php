<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

use SensitiveParameter;

/**
 * Hashes and verifies user passwords.
 *
 * A port so the algorithm and cost are configurable and swappable by the host.
 * The default implementation uses Argon2id and is compatible with the framework's
 * {@see \Altair\Http\Validator\RepositoryIdentityValidator}, which verifies via
 * the native {@see \password_verify()}.
 */
interface PasswordHasherInterface
{
    /**
     * Hash a plaintext password into a self-describing hash string.
     */
    public function hash(#[SensitiveParameter] string $plain): string;

    /**
     * Verify a plaintext password against a stored hash, in constant time.
     */
    public function verify(#[SensitiveParameter] string $plain, string $hash): bool;

    /**
     * Whether the stored hash was produced with outdated parameters and should be
     * re-hashed on the next successful authentication.
     */
    public function needsRehash(string $hash): bool;
}
