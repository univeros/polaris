<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\RecoveryCode;
use Univeros\Polaris\Security\Pepper;

use function random_int;
use function strlen;

/**
 * Issues single-use MFA recovery codes.
 *
 * A batch of {@see COUNT} codes is generated, each formatted `xxxxx-xxxxx` from an unambiguous
 * base32 alphabet (no `0/1/8/9/O/I/L`), returned **once** to the caller, and stored only as a keyed
 * HMAC ({@see Pepper}, `recovery` context) — never in plaintext. Rows are persisted via the unit of
 * work; the caller flushes, so issuance commits atomically with the confirm that triggered it.
 *
 * (Verify-with-recovery-code and regenerate-batch land in issue #24 and extend this service.)
 */
final readonly class RecoveryCodeService
{
    /** Codes per batch. */
    public const int COUNT = 10;

    private const string PEPPER_CONTEXT = 'recovery';
    private const string ALPHABET = 'abcdefghjkmnpqrstuvwxyz234567';
    private const int GROUP_LENGTH = 5;

    public function __construct(
        private UnitOfWorkInterface $unitOfWork,
        private Pepper $pepper,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Generate, persist (hashed), and return a fresh batch of plaintext recovery codes.
     *
     * @return list<string>
     */
    public function issue(string $userId): array
    {
        $now = $this->clock->now();
        $codes = [];

        for ($i = 0; $i < self::COUNT; ++$i) {
            $code = $this->generateCode();
            $codes[] = $code;

            $entity = new RecoveryCode();
            $entity->id = Uuid::v7()->toRfc4122();
            $entity->userId = $userId;
            $entity->codeHash = $this->pepper->hash(self::PEPPER_CONTEXT, $code);
            $entity->createdAt = $now;
            $this->unitOfWork->persist($entity);
        }

        return $codes;
    }

    private function generateCode(): string
    {
        return $this->group() . '-' . $this->group();
    }

    private function group(): string
    {
        $max = strlen(self::ALPHABET) - 1;
        $group = '';
        for ($i = 0; $i < self::GROUP_LENGTH; ++$i) {
            $group .= self::ALPHABET[random_int(0, $max)];
        }

        return $group;
    }
}
