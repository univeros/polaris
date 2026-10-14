<?php

declare(strict_types=1);

namespace Univeros\Polaris\Messaging;

use Polaris\Messaging\Sender;
use Polaris\Polaris;
use RuntimeException;

use function sprintf;

/**
 * Delivers a queued {@see SendMessage} through the channels and the fallback (`Sender::dispatch()`: no
 * second policy check, no outbox). Registered with Univeros Messaging by the module. When no channel
 * delivered it, it throws, so the transport retries it and then hands it to the failure transport.
 */
final readonly class SendMessageHandler
{
    public function __construct(private Polaris $polaris)
    {
    }

    public function __invoke(SendMessage $send): void
    {
        if ($this->polaris->graph()->get(Sender::class)->dispatch($send->message, $send->alternatives) === null) {
            throw new RuntimeException(sprintf('No channel delivered the %s message %s.', $send->message->kind, $send->message->template));
        }
    }
}
