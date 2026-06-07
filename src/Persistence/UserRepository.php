<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\User;

/**
 * Cycle-backed repository for {@see User}, pinned to the entity so callers and the
 * container resolve a single, autowireable type. The ORM and unit of work are bound
 * by `univeros/persistence`, so the module needs no extra wiring to obtain one.
 *
 * @extends CycleRepository<User>
 */
final class UserRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(User::class, $orm, $unitOfWork);
    }
}
