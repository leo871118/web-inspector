<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Represents a single DNS MX (Mail Exchanger) entry.
 */
final readonly class MxRecord implements JsonSerializable
{
    public function __construct(
        public string $host,
        public int $priority,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'host' => $this->host,
            'priority' => $this->priority,
        ];
    }
}
