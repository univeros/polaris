<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use DateTimeImmutable;
use Override;
use Psr\Clock\ClockInterface;

/**
 * A PSR-20 clock pinned to a fixed instant, so token issued-at / expiry / not-before
 * behaviour is deterministic and the time window can be advanced explicitly in tests.
 */
final class FrozenClock implements ClockInterface
{
    public function __construct(private DateTimeImmutable $now)
    {
    }

    public static function at(string $time): self
    {
        return new self(new DateTimeImmutable($time));
    }

    #[Override]
    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
