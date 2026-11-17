<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Represents a single security, performance, SEO, or infrastructure finding.
 */
final readonly class DiagnosticFinding implements JsonSerializable
{
    public function __construct(
        public Severity $severity,
        public string $category,
        public string $title,
        public string $detail,
        public ?string $recommendation = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'severity' => $this->severity->value,
            'category' => $this->category,
            'title' => $this->title,
            'detail' => $this->detail,
            'recommendation' => $this->recommendation,
        ];
    }
}
