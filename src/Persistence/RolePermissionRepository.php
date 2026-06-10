<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\RolePermission;

/**
 * Cycle-backed repository for {@see RolePermission}, pinned to the entity so callers and the
 * container resolve a single, autowireable type.
 *
 * @extends CycleRepository<RolePermission>
 */
final class RolePermissionRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(RolePermission::class, $orm, $unitOfWork);
    }
}
