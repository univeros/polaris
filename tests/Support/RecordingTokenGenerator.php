<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Http\Contracts\TokenGeneratorInterface;
use Override;

use function count;

/**
 * A {@see TokenGeneratorInterface} that records the claim sets it is asked to mint and
 * returns a deterministic marker string, so tests can assert claim assembly without
 * parsing real JWTs.
 */
final class RecordingTokenGenerator implements TokenGeneratorInterface
{
    /** @var list<array<string, mixed>> */
    public array $claims = [];

    /**
     * @param array<string, mixed> $claims
     */
    #[Override]
    public function generate(array $claims = []): string
    {
        $this->claims[] = $claims;

        return 'access-token-' . count($this->claims);
    }
}
