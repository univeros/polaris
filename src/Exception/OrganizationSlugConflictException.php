<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

use RuntimeException;

/**
 * Thrown when creating an organization with a slug that is already taken. The endpoint maps this to
 * `409 conflict` — slugs are unique across the deployment.
 */
final class OrganizationSlugConflictException extends RuntimeException
{
    public function __construct(public readonly string $slug)
    {
        parent::__construct('The organization slug is already taken.');
    }
}
