<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Altair\Persistence\Contracts\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Cycle\ORM\ORMInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Univeros\Polaris\Entity\RecoveryCode;
use Univeros\Polaris\Event\MfaRecoveryRegenerated;
use Univeros\Polaris\Event\MfaRecoveryUsed;
use Univeros\Polaris\Security\Pepper;

use function count;
use function random_int;
use function strlen;

/**
 * Issues, verifies, and regenerates single-use MFA recovery codes.
 *
 * A batch of {@see COUNT} codes is generated, each formatted `xxxxx-xxxxx` from an unambiguous
 * base32 alphabet (no `0/1/8/9/O/I/L`), returned **once** to the caller, and stored only as a keyed
 * HMAC ({@see Pepper}, `recovery` context) — never in plaintext. A code is spent at verify by
 * stamping {@see RecoveryCode::$usedAt}; the same stamp retires the prior batch on regenerate, so a
 * code can satisfy at most one verify. Rows are written through the unit of work — {@see issue()}
 * leaves the flush to its caller (so issuance commits atomically with the confirm that triggered
 * it), while {@see verify()} and {@see regenerate()} flush their own mutation.
 */
final readonly class RecoveryCodeService
{
    /** Codes per batch. */
    public const int COUNT = 10;

    private const string PEPPER_CONTEXT = 'recovery';
    private const string ALPHABET = 'abcdefghjkmnpqrstuvwxyz234567';
    private const int GROUP_LENGTH = 5;

    /**
     * @param RepositoryInterface<RecoveryCode> $codes
     */
    public function __construct(
        private RepositoryInterface $codes,
        private UnitOfWorkInterface $unitOfWork,
        private Pepper $pepper,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private ?ORMInterface $orm = null,
    ) {
    }

    /**
     * Generate, persist (hashed), and return a fresh batch of plaintext recovery codes.
     *
     * The caller flushes the unit of work; see the class note.
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

    /**
     * Spend a recovery code: if it matches one of the user's unused codes, stamp it used and return
     * true; otherwise return false having changed nothing. Single-use — a matched code cannot be
     * replayed.
     *
     * Every unused row is compared (no early return) so the work — and thus the timing — does not
     * depend on which code matched. The spend is an atomic compare-and-swap on `used_at` (as in
     * refresh rotation): of two concurrent verifies of the same code, exactly one spends it and
     * the other fails as if the code were already used.
     */
    public function verify(string $userId, #[SensitiveParameter] string $code): bool
    {
        $match = null;
        $unused = 0;
        foreach ($this->unusedFor($userId) as $candidate) {
            $unused++;
            if ($this->pepper->matches(self::PEPPER_CONTEXT, $code, $candidate->codeHash)) {
                $match = $candidate;
            }
        }

        if ($match === null) {
            return false;
        }

        $now = $this->clock->now();
        if (!$this->claimSpend($match, $now)) {
            return false;
        }

        $match->usedAt = $now;
        $this->unitOfWork->persist($match);
        $this->unitOfWork->flush();

        $this->events->dispatch(new MfaRecoveryUsed($userId, $unused - 1));

        return true;
    }

    /**
     * Claim the code's single use with one conditional UPDATE; false means another request spent
     * it first.
     */
    private function claimSpend(RecoveryCode $code, DateTimeImmutable $now): bool
    {
        if ($this->orm === null) {
            // In-memory test wiring has no database to CAS against; the entity-level
            // used_at check already ran in unusedFor(). Production wiring passes the ORM.
            return true;
        }

        $source = $this->orm->getSource(RecoveryCode::class);
        $affected = $source->getDatabase()->update(
            $source->getTable(),
            ['used_at' => $now],
            ['id' => $code->id, 'used_at' => null],
        )->run();

        return $affected === 1;
    }

    /**
     * Retire every still-unused code (so the prior batch can no longer authenticate), issue a fresh
     * batch, and return the new plaintext codes. Emits {@see MfaRecoveryRegenerated}.
     *
     * @return list<string>
     */
    public function regenerate(string $userId): array
    {
        $now = $this->clock->now();
        foreach ($this->unusedFor($userId) as $code) {
            $code->usedAt = $now;
            $this->unitOfWork->persist($code);
        }

        $codes = $this->issue($userId);
        $this->unitOfWork->flush();

        $this->events->dispatch(new MfaRecoveryRegenerated($userId));

        return $codes;
    }

    /**
     * How many of the user's recovery codes are still unused — the signal a host surfaces (e.g. ≤3
     * left) to prompt regeneration.
     */
    public function remaining(string $userId): int
    {
        return count($this->unusedFor($userId));
    }

    /**
     * The user's still-spendable codes: persisted rows with no `used_at` stamp.
     *
     * The query is scoped to `used_at IS NULL` so it stays bounded as spent rows accumulate over an
     * account's lifetime (served by the `auth_recovery_codes (user_id, used_at)` index). The
     * in-PHP re-check is the authoritative single-use guard: a spent code is never treated as live
     * even if a repository ignored the scope.
     *
     * @return list<RecoveryCode>
     */
    private function unusedFor(string $userId): array
    {
        $unused = [];
        foreach ($this->codes->findBy(['userId' => $userId, 'usedAt' => null]) as $code) {
            if ($code->usedAt === null) {
                $unused[] = $code;
            }
        }

        return $unused;
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
