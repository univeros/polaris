<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\RefreshToken;

/**
 * Cycle-backed repository for {@see RefreshToken}, pinned to the entity. Lookups by
 * `tokenHash` (refresh exchange) and `familyId` (family revocation) drive the rotation
 * and reuse-detection flow in {@see \Univeros\Polaris\Token\TokenService}.
 *
 * @extends CycleRepository<RefreshToken>
 */
final class RefreshTokenRepository extends CycleRepository
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(RefreshToken::class, $orm, $unitOfWork);
    }
}
