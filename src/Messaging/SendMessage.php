<?php

declare(strict_types=1);

namespace Univeros\Polaris\Messaging;

use Polaris\Messaging\Message;

/**
 * A Polaris send on the Univeros Messaging bus: the message, already rendered and allowed by the policy,
 * and the alternative recipients its fallback may use. Serializable, so any transport carries it.
 */
final readonly class SendMessage
{
    /**
     * @param array<string, string> $alternatives kind => recipient
     */
    public function __construct(public Message $message, public array $alternatives = [])
    {
    }
}
