<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Altair\Http\Contracts\IdentityProviderInterface;
use Altair\Persistence\Contracts\RepositoryInterface;
use Override;
use Univeros\Polaris\Entity\User;

/**
 * Adapts the {@see User} repository to the framework's {@see IdentityProviderInterface}
 * so HTTP authentication can look an identity up without depending on the ORM.
 *
 * The framework's {@see \Altair\Http\Validator\RepositoryIdentityValidator} calls
 * {@see findOneBy()} with the configured identifier field (`email`) and then reads
 * the password hash from the returned record under the configured key
 * (`password_hash`). The record is therefore keyed by **database column names** —
 * the same names the validator is wired with — rather than entity property names.
 *
 * The record is deliberately limited to the fields credential validation needs
 * (identifier + hash), to keep the password hash from travelling alongside profile
 * or policy data that a caller might inadvertently log or serialise. This is a
 * password-only credential check: account `status`/lockout, MFA, and the dummy-
 * verify timing equalization that prevents user enumeration are the login flow's
 * responsibility (see `docs/auth/flows.md` §login and `docs/auth/security.md` §4),
 * which reads them from the {@see User} entity, not from this record.
 */
final class CycleIdentityProvider implements IdentityProviderInterface
{
    /**
     * The User field the login identifier is matched against. Fixed to `email` for
     * this build (the documented primary identifier); also the criterion key the
     * validator is wired with.
     */
    public const string IDENTIFIER_FIELD = 'email';

    /** The record key under which the validator finds the stored password hash. */
    public const string PASSWORD_HASH_FIELD = 'password_hash';

    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(private readonly RepositoryInterface $users)
    {
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return array<string, mixed>|null
     */
    #[Override]
    public function findOneBy(array $criteria): ?array
    {
        $user = $this->users->findOneBy($criteria);

        return $user instanceof User ? $this->toRecord($user) : null;
    }

    /**
     * The identity as a minimal, column-keyed credential record: the subject id, the
     * login identifier, and the stored hash the validator verifies against. Values
     * stay as their native PHP types; the validator only stringifies the hash.
     *
     * @return array{id: string, email: string, password_hash: ?string}
     */
    private function toRecord(User $user): array
    {
        return [
            'id' => $user->id,
            self::IDENTIFIER_FIELD => $user->email,
            self::PASSWORD_HASH_FIELD => $user->passwordHash,
        ];
    }
}
