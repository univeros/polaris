<?php

declare(strict_types=1);

namespace Univeros\Polaris\Contracts;

/**
 * Renders arbitrary data (typically an `otpauth://` provisioning URI) as a QR code.
 *
 * A port over the underlying library ({@see \Univeros\Polaris\Mfa\EndroidQrRenderer} wraps
 * `endroid/qr-code`). SVG is the default output: it is vector (crisp at any size) and needs no
 * `gd`/`imagick` extension, so TOTP enrollment works on a stock PHP install.
 */
interface QrCodeRendererInterface
{
    /**
     * Render `$data` as a standalone SVG document (markup string).
     *
     * The caller is responsible for `$data` being a trusted value (e.g. a generated `otpauth://`
     * URI), not raw user input — a QR encodes whatever payload it is given.
     */
    public function svg(string $data): string;
}
