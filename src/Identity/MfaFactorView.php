<?php

declare(strict_types=1);

namespace Univeros\Polaris\Identity;

use Univeros\Polaris\Entity\MfaFactor;
use Univeros\Polaris\Mfa\Destination;

/**
 * A confirmed factor as the client sees it during the login MFA challenge: enough to choose and
 * label a factor, never enough to reveal a secret or full destination. Built from a {@see MfaFactor}
 * with its sms/email destination already {@see Destination::mask masked}.
 */
final readonly class MfaFactorView
{
    public function __construct(
        public string $id,
        public string $type,
        public ?string $label,
        public ?string $maskedDestination,
        public bool $isDefault,
    ) {
    }

    public static function of(MfaFactor $factor): self
    {
        $destination = match ($factor->type) {
            MfaFactor::TYPE_SMS => (string) $factor->phoneE164,
            MfaFactor::TYPE_EMAIL => (string) $factor->email,
            default => '',
        };

        return new self(
            $factor->id,
            $factor->type,
            $factor->label,
            $destination === '' ? null : Destination::mask($factor->type, $destination),
            $factor->isDefault,
        );
    }

    /**
     * The wire shape (spec §5): `id`/`type`/`default` always, `label` and `destination` only when
     * present (a TOTP factor has no destination; an unlabelled factor omits `label`).
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $view = ['id' => $this->id, 'type' => $this->type, 'default' => $this->isDefault];

        if ($this->label !== null && $this->label !== '') {
            $view['label'] = $this->label;
        }

        if ($this->maskedDestination !== null) {
            $view['destination'] = $this->maskedDestination;
        }

        return $view;
    }
}
