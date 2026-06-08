<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Override;
use Psr\Log\AbstractLogger;
use Stringable;

/**
 * A PSR-3 logger that records every entry, so tests can assert what a log-based driver emitted.
 */
final class RecordingLogger extends AbstractLogger
{
    /** @var list<array{level: mixed, message: string, context: array<string, mixed>}> */
    public array $records = [];

    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
    }
}
