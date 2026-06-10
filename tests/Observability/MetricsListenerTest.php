<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Observability;

use Altair\Observability\Metrics\Meter;
use Altair\Observability\Recorder\InMemoryRecorder;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Univeros\Polaris\Event\RefreshReuseDetected;
use Univeros\Polaris\Event\UserLoggedIn;
use Univeros\Polaris\Event\UserLoginFailed;
use Univeros\Polaris\Event\UserRegistered;
use Univeros\Polaris\Observability\MetricsListener;

/**
 * Verifies the #42 {@see MetricsListener}: every Polaris domain event increments the
 * `polaris.auth.events` counter with its catalog name as the `event` attribute (alert rules
 * filter on it), unrelated objects are ignored, and the token on a secret-carrying event never
 * reaches a metric attribute.
 */
final class MetricsListenerTest extends TestCase
{
    public function testCountsEventsWithTheirCatalogName(): void
    {
        $recorder = new InMemoryRecorder();
        $listener = new MetricsListener(new Meter($recorder), new NullLogger());

        $listener(new UserLoggedIn('user-1', 'session-1', '203.0.113.7'));
        $listener(new UserLoginFailed('user-1', '203.0.113.7'));
        $listener(new RefreshReuseDetected('user-1', 'family-1', null));

        $points = $recorder->metrics();
        self::assertCount(3, $points);
        self::assertSame('polaris.auth.events', $points[0]->name);
        self::assertSame(['event' => 'user.logged_in'], $points[0]->attributes);
        self::assertSame(['event' => 'user.login_failed'], $points[1]->attributes);
        self::assertSame(['event' => 'auth.refresh_reuse_detected'], $points[2]->attributes);
        self::assertSame(1.0, $points[0]->value);
    }

    public function testSecretCarryingEventsExposeOnlyTheirName(): void
    {
        $recorder = new InMemoryRecorder();
        $listener = new MetricsListener(new Meter($recorder), new NullLogger());

        $listener(new UserRegistered('user-1', 'new@example.com', 'verification-secret-token'));

        $points = $recorder->metrics();
        self::assertCount(1, $points);
        self::assertSame(['event' => 'user.registered'], $points[0]->attributes);
    }

    public function testIgnoresObjectsOutsideTheEventNamespace(): void
    {
        $recorder = new InMemoryRecorder();
        $listener = new MetricsListener(new Meter($recorder), new NullLogger());

        $listener(new class () {
            public const string NAME = 'not.a.polaris.event';
        });

        self::assertCount(0, $recorder->metrics());
    }
}
