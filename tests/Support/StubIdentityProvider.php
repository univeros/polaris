<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Http\Contracts\IdentityProviderInterface;
use Override;

use function is_string;

/**
 * In-memory {@see IdentityProviderInterface} keyed by email, for token-factory tests
 * that need to resolve a subject without a database.
 */
final class StubIdentityProvider implements IdentityProviderInterface
{
    /**
     * @param array<string, array<string, mixed>> $recordsByEmail
     */
    public function __construct(private array $recordsByEmail = [])
    {
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return array<string, mixed>|null
     */
    #[Override]
    public function findOneBy(array $criteria): ?array
    {
        $email = $criteria['email'] ?? null;

        return is_string($email) ? ($this->recordsByEmail[$email] ?? null) : null;
    }
}
