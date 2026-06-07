<?php

declare(strict_types=1);

namespace Univeros\Polaris\Security;

use SensitiveParameter;
use Univeros\Polaris\Contracts\PasswordHasherInterface;

use function password_hash;
use function password_needs_rehash;
use function password_verify;

use const PASSWORD_ARGON2ID;

/**
 * Argon2id password hasher (OWASP-recommended memory-hard hashing).
 *
 * Cost parameters are configurable so a host can tune them to its hardware and
 * raise them over time; {@see needsRehash()} then upgrades stored hashes lazily
 * on the next successful login.
 */
final class Argon2idPasswordHasher implements PasswordHasherInterface
{
    /**
     * @var array{memory_cost: int, time_cost: int, threads: int}
     */
    private const DEFAULTS = [
        'memory_cost' => 65536, // 64 MiB
        'time_cost' => 4,
        'threads' => 1,
    ];

    /**
     * @var array{memory_cost: int, time_cost: int, threads: int}
     */
    private array $options;

    /**
     * @param array{memory_cost?: int, time_cost?: int, threads?: int} $options
     */
    public function __construct(array $options = [])
    {
        $this->options = [
            'memory_cost' => $options['memory_cost'] ?? self::DEFAULTS['memory_cost'],
            'time_cost' => $options['time_cost'] ?? self::DEFAULTS['time_cost'],
            'threads' => $options['threads'] ?? self::DEFAULTS['threads'],
        ];
    }

    public function hash(#[SensitiveParameter] string $plain): string
    {
        return password_hash($plain, PASSWORD_ARGON2ID, $this->options);
    }

    public function verify(#[SensitiveParameter] string $plain, string $hash): bool
    {
        return $hash !== '' && password_verify($plain, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, $this->options);
    }
}
