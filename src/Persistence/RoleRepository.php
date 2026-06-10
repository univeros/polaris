<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\Role;

/**
 * Cycle-backed repository for {@see Role}, pinned to the entity so callers and the container
 * resolve a single, autowireable type.
 *
 * @extends CycleRepository<Role>
 */
final class RoleRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(Role::class, $orm, $unitOfWork);
    }
}
