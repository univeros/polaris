<?php

declare(strict_types=1);

namespace Univeros\Polaris\Config;

use Altair\Http\Middleware\RateLimit\RateLimit;

use function is_array;

/**
 * The per-group rate-limit budgets for the auth endpoints, as a typed, validated value object.
 *
 * Each group is a framework {@see RateLimit} policy (limit + fixed window + a distinct cache-key
 * prefix so the groups don't collide on a shared backend). Defaults come from
 * `docs/auth/security.md §5`; a host overrides any subset via {@see self::fromArray()} (the
 * `auth.rate_limits` config namespace), leaving the rest at their defaults.
 *
 * Only the groups whose routes exist in this phase are modelled (login, register,
 * password/forgot, token/refresh). The composite IP+account keys and the user-id "global
 * authenticated" budget from the spec arrive with later phases.
 */
final readonly class RateLimitConfig
{
    private const int LOGIN_LIMIT = 10;
    private const int LOGIN_WINDOW = 300;
    private const int REGISTER_LIMIT = 5;
    private const int REGISTER_WINDOW = 3600;
    private const int PASSWORD_FORGOT_LIMIT = 5;
    private const int PASSWORD_FORGOT_WINDOW = 3600;
    private const int TOKEN_REFRESH_LIMIT = 60;
    private const int TOKEN_REFRESH_WINDOW = 60;

    public function __construct(
        public RateLimit $login,
        public RateLimit $register,
        public RateLimit $passwordForgot,
        public RateLimit $tokenRefresh,
    ) {
    }

    public static function defaults(): self
    {
        return self::fromArray([]);
    }

    /**
     * @param array<string, mixed> $limits the host's `auth.rate_limits` namespace. Each group key
     *   (`login`, `register`, `password_forgot`, `token_refresh`) takes an array of overrides:
     *   `limit` (max requests per window) and `window` (window length in seconds). Any group or
     *   key left out keeps its default.
     */
    public static function fromArray(array $limits): self
    {
        return new self(
            login: self::policy($limits, 'login', self::LOGIN_LIMIT, self::LOGIN_WINDOW, 'auth.login'),
            register: self::policy($limits, 'register', self::REGISTER_LIMIT, self::REGISTER_WINDOW, 'auth.register'),
            passwordForgot: self::policy(
                $limits,
                'password_forgot',
                self::PASSWORD_FORGOT_LIMIT,
                self::PASSWORD_FORGOT_WINDOW,
                'auth.password_forgot',
            ),
            tokenRefresh: self::policy(
                $limits,
                'token_refresh',
                self::TOKEN_REFRESH_LIMIT,
                self::TOKEN_REFRESH_WINDOW,
                'auth.token_refresh',
            ),
        );
    }

    /**
     * @param array<string, mixed> $limits
     */
    private static function policy(array $limits, string $key, int $limit, int $window, string $prefix): RateLimit
    {
        $group = is_array($limits[$key] ?? null) ? $limits[$key] : [];

        return new RateLimit(
            (int) ($group['limit'] ?? $limit),
            (int) ($group['window'] ?? $window),
            $prefix,
        );
    }
}
