<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Aggregated audit report for HTTP security response headers.
 */
final readonly class SecurityHeadersReport implements JsonSerializable
{
    /**
     * @param array<string, HeaderCheckResult> $headers
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public int $score,
        public string $grade,
        public array $headers,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'score' => $this->score,
            'grade' => $this->grade,
            'headers' => array_map(
                static fn(HeaderCheckResult $item): array => $item->jsonSerialize(),
                $this->headers,
            ),
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
