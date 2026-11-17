<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Result of inspecting a single HTTP security header.
 */
final readonly class HeaderCheckResult implements JsonSerializable
{
    /**
     * @param array<string, mixed> $meta
     */
    public function __construct(
        public bool $present,
        public ?string $value = null,
        public array $meta = [],
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'present' => $this->present,
            'value' => $this->value,
            'meta' => $this->meta,
        ];
    }
}
