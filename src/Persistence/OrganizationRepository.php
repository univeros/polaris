<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\Organization;

/**
 * Cycle-backed repository for {@see Organization}, pinned to the entity so callers and the container
 * resolve a single, autowireable type.
 *
 * @extends CycleRepository<Organization>
 */
final class OrganizationRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(Organization::class, $orm, $unitOfWork);
    }
}
