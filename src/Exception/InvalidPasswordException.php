<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when a submitted password fails the password policy. Carries the list of failed
 * rules so the endpoint can return a `422` problem detail — this is about the submitted
 * password, not account existence, so it is not an enumeration signal.
 */
final class InvalidPasswordException extends RuntimeException
{
    /**
     * @param list<string> $violations
     */
    public function __construct(public readonly array $violations)
    {
        parent::__construct('The password does not meet the policy requirements.');
    }
}
