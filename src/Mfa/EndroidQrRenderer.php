<?php

declare(strict_types=1);

namespace Univeros\Polaris\Mfa;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\ErrorCorrectionLevel;
use Endroid\QrCode\Writer\SvgWriter;
use Override;
use Univeros\Polaris\Contracts\QrCodeRendererInterface;

/**
 * QR rendering via `endroid/qr-code`, emitting SVG.
 *
 * SVG needs no `gd`/`imagick` extension, so TOTP enrollment renders on a stock PHP install.
 * Medium error correction keeps the code scannable if the displayed image is slightly degraded.
 */
final class EndroidQrRenderer implements QrCodeRendererInterface
{
    #[Override]
    public function svg(string $data): string
    {
        return (new Builder(
            writer: new SvgWriter(),
            data: $data,
            errorCorrectionLevel: ErrorCorrectionLevel::Medium,
        ))->build()->getString();
    }
}
