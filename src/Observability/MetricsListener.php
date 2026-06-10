<?php

declare(strict_types=1);

namespace Univeros\Polaris\Observability;

use Altair\Observability\Metrics\Meter;
use Psr\Log\LoggerInterface;
use Throwable;

use function constant;
use function defined;
use function is_string;
use function str_starts_with;

/**
 * PSR-14 listener counting every Polaris domain event as an OpenTelemetry-style metric via the
 * framework {@see Meter} (`univeros/observability`): one `polaris.auth.events` counter with an
 * `event` attribute carrying the catalog name (`docs/auth/events.md`). Alert rules filter on the
 * attribute, e.g. `event = auth.refresh_reuse_detected`, spikes of `user.login_failed` /
 * `user.locked` / `mfa.verify_failed`, and `org.deleted` (`docs/auth/security.md` §8).
 *
 * Subscribe it to the host's dispatcher alongside the audit and notification listeners. Any
 * Polaris event class is covered automatically through its `NAME` constant, so new events need no
 * change here. Per-request span latencies come from the framework's `ObservabilityMiddleware`,
 * which the host wires; this listener contributes the domain-level signal.
 *
 * **Fail-open:** like its siblings, a metrics failure is logged (PSR-3) and swallowed.
 */
final class MetricsListener
{
    private const string COUNTER = 'polaris.auth.events';
    private const string EVENT_NAMESPACE = 'Univeros\\Polaris\\Event\\';

    public function __construct(
        private readonly Meter $meter,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function __invoke(object $event): void
    {
        if (!str_starts_with($event::class, self::EVENT_NAMESPACE) || !defined($event::class . '::NAME')) {
            return;
        }

        $name = constant($event::class . '::NAME');
        if (!is_string($name)) {
            return;
        }

        try {
            $this->meter->counter(self::COUNTER, 1.0, ['event' => $name], description: 'Polaris auth domain events');
        } catch (Throwable $exception) {
            $this->logger->error('Metrics emission failed for {event}: {reason}', [
                'event' => $name,
                'reason' => $exception->getMessage(),
                'exception' => $exception,
            ]);
        }
    }
}
