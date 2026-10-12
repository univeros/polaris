<?php

declare(strict_types=1);

namespace Univeros\Polaris\Observability;

use Altair\Observability\Metrics\Meter;
use Override;
use Polaris\Contract\MetricsInterface;

/**
 * Polaris's counters through Univeros Observability's {@see Meter}: what the module binds as the metrics
 * port when the host binds a `Meter` (`ObservabilityConfiguration`) and no `MetricsInterface` of its own.
 */
final readonly class MeterMetrics implements MetricsInterface
{
    public function __construct(private Meter $meter)
    {
    }

    #[Override]
    public function counter(string $name, float $value = 1.0, array $attributes = [], ?string $description = null): void
    {
        $this->meter->counter($name, $value, $attributes, description: $description);
    }
}
