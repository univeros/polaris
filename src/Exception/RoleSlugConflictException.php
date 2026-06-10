<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when creating a role with a slug the organization already uses. The endpoint maps this
 * to `409 conflict`.
 */
final class RoleSlugConflictException extends RuntimeException
{
    public function __construct(string $slug)
    {
        parent::__construct("The role slug \"$slug\" is already taken in this organization.");
    }
}
