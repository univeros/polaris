<?php

declare(strict_types=1);

namespace Univeros\Polaris\Exception;

/**
 * Thrown when an already-rotated refresh token is replayed — a stolen-token signal. By
 * the time this is thrown the entire token family has been revoked and
 * {@see \Univeros\Polaris\Event\RefreshReuseDetected} has been dispatched.
 *
 * It extends {@see InvalidGrantException} so the refresh endpoint's single
 * `invalid_grant` catch covers it, while remaining a distinct type for logging/alerting.
 */
final class RefreshTokenReuseException extends InvalidGrantException
{
}
