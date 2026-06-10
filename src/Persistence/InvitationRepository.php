<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\Invitation;

/**
 * Cycle-backed repository for {@see Invitation}, pinned to the entity so callers and the container
 * resolve a single, autowireable type.
 *
 * @extends CycleRepository<Invitation>
 */
final class InvitationRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(Invitation::class, $orm, $unitOfWork);
    }
}
