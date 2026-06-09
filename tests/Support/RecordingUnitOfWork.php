<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Support;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Override;

/**
 * An in-memory {@see UnitOfWorkInterface} that records what was persisted, so a service can be
 * unit-tested without a database.
 */
final class RecordingUnitOfWork implements UnitOfWorkInterface
{
    /** @var list<object> */
    public array $persisted = [];

    /** @var list<object> */
    public array $removed = [];

    public int $flushes = 0;

    #[Override]
    public function persist(object $entity): void
    {
        $this->persisted[] = $entity;
    }

    #[Override]
    public function remove(object $entity): void
    {
        $this->removed[] = $entity;
    }

    #[Override]
    public function flush(): void
    {
        ++$this->flushes;
    }

    #[Override]
    public function clear(): void
    {
    }
}
