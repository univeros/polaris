<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Override;
use Univeros\Polaris\Contracts\SmsSenderInterface;

/**
 * A no-op SMS driver for environments that disable the SMS channel entirely (it neither sends
 * nor logs). Bind this as {@see SmsSenderInterface} to silently drop SMS delivery.
 */
final class NullSmsSender implements SmsSenderInterface
{
    #[Override]
    public function send(string $toE164, string $message): void
    {
    }
}
