<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Messaging;

use Altair\Container\Container;
use Altair\Messaging\Configuration\MessengerConfiguration;
use Altair\Messaging\Configuration\TransportSettings;
use Altair\Messaging\Contracts\MessageBusInterface;
use Altair\Messaging\Transport\TransportLocator;
use Altair\Module\ModuleConfiguration;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\AuditPlugin;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Messaging\Channel\ArrayChannel;
use Polaris\Messaging\Message;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Messaging\Sender;
use Polaris\Testing\InMemoryAdapter;
use RuntimeException;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Messenger\Transport\TransportInterface;
use Univeros\Polaris\Messaging\BusOutbox;
use Univeros\Polaris\Messaging\SendMessage;
use Univeros\Polaris\Module;
use Univeros\Polaris\Plugins;
use Univeros\Polaris\Tests\Support\TestPolaris;

final class BusOutboxTest extends TestCase
{
    public function testASendLeavesTheRequestAndTheWorkerDeliversItOnce(): void
    {
        $mail = new ArrayChannel('mail', [Message::EMAIL]);
        $container = self::boot($mail);
        $sender = TestPolaris::graph($container)->get(Sender::class);

        $receipt = $sender->send(Message::EMAIL, 'ada@example.com', 'email.otp', ['code' => '424242', 'ttl' => 300]);
        self::assertTrue($receipt?->queued, 'the request gets a queued receipt');
        self::assertCount(0, $mail->messages, 'nothing is delivered on the request');
        self::assertNull($sender->send(Message::EMAIL, 'ada@example.com', 'email.otp', ['code' => '1', 'ttl' => 300]), 'the cap of 1 counted the queued send');

        $envelopes = [...self::transport($container)->get()];
        self::assertCount(1, $envelopes, 'one serialized SendMessage on the async transport');
        self::worker($container, $envelopes[0]->getMessage());

        self::assertCount(1, $mail->messages, 'the worker delivers past the cap the request already used');
        self::assertSame('email.otp', $mail->messages[0]->template);
        self::assertCount(1, [...self::transport($container)->get()], 'delivery never comes back to the bus');
    }

    public function testTheWorkerFailsWhenNoChannelDelivers(): void
    {
        $container = self::boot(new ArrayChannel('mail', [Message::EMAIL]));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('No channel delivered the sms message sms.otp.');
        self::worker($container, new SendMessage(new Message(Message::SMS, '+15551234567', 'sms.otp', 'code 1')));
    }

    private static function boot(ArrayChannel $mail): Container
    {
        $container = new Container();
        $container->instance(DatabaseAdapter::class, new InMemoryAdapter());
        $container->instance(Secrets::class, TestPolaris::secrets());
        $container->instance(AuthConfig::class, TestPolaris::auth());
        (new MessengerConfiguration())->apply($container);
        $container->instance(TransportSettings::class, new TransportSettings(['async' => 'in-memory://?serialize=true'], [SendMessage::class => ['async']]));
        $container->instance(Plugins::class, new Plugins(
            new AuditPlugin(),
            new MessagingPlugin(
                channels: [$mail],
                caps: ['*' => [1, 600]],
                outbox: new BusOutbox(static fn(): MessageBusInterface => $container->get(MessageBusInterface::class)),
            ),
        ));
        (new ModuleConfiguration([new Module()]))->apply($container);

        return $container;
    }

    private static function transport(Container $container): TransportInterface
    {
        $locator = $container->get(TransportLocator::class);
        \assert($locator instanceof TransportLocator);

        return $locator->get('async');
    }

    /**
     * What `bin/altair messenger:consume` does with a received message: handle it, without sending.
     */
    private static function worker(Container $container, object $message): void
    {
        $bus = $container->get(MessageBusInterface::class);
        \assert($bus instanceof MessageBusInterface);
        $bus->dispatch($message, [new ReceivedStamp('async')]);
    }
}
