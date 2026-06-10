<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\MembershipRole;

/**
 * Cycle-backed repository for {@see MembershipRole}, pinned to the entity so callers and the
 * container resolve a single, autowireable type.
 *
 * @extends CycleRepository<MembershipRole>
 */
final class MembershipRoleRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(MembershipRole::class, $orm, $unitOfWork);
    }
}
