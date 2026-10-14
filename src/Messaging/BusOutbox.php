<?php

declare(strict_types=1);

namespace Univeros\Polaris\Messaging;

use Altair\Messaging\Contracts\MessageBusInterface;
use Closure;
use DateTimeImmutable;
use Override;
use Polaris\Messaging\Message;
use Polaris\Messaging\Outbox;
use Polaris\Messaging\Receipt;

/**
 * polaris/messaging's outbox on the Univeros Messaging bus: a send leaves the request as a
 * {@see SendMessage}, routed by `MESSENGER_ROUTING` (unrouted, the bus handles it on the spot), and
 * {@see SendMessageHandler} delivers it in the worker. The caller gets `Receipt::queued()`.
 */
final class BusOutbox implements Outbox
{
    /**
     * @param Closure(): MessageBusInterface $bus resolved at the first send
     */
    public function __construct(private readonly Closure $bus)
    {
    }

    #[Override]
    public function push(Message $message, array $alternatives): Receipt
    {
        ($this->bus)()->dispatch(new SendMessage($message, $alternatives));

        return Receipt::queued(new DateTimeImmutable());
    }
}
