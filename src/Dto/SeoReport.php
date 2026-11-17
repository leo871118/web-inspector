<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Structured report for On-Page SEO metadata, social cards, and JSON-LD entities.
 */
final readonly class SeoReport implements JsonSerializable
{
    /**
     * @param list<string> $h1Items
     * @param array{present: bool, title: ?string, description: ?string, image: ?string, type: ?string, url: ?string} $openGraph
     * @param array{present: bool, card: ?string, title: ?string, image: ?string} $twitterCard
     * @param list<string> $schemaTypes
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public ?string $title,
        public int $titleLength,
        public ?string $description,
        public int $descriptionLength,
        public ?string $canonicalUrl,
        public bool $canonicalMismatch,
        public ?string $robotsMeta,
        public bool $isNoindex,
        public int $h1Count,
        public array $h1Items,
        public array $openGraph,
        public array $twitterCard,
        public int $schemaBlocksCount,
        public array $schemaTypes,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'title' => $this->title,
            'title_length' => $this->titleLength,
            'description' => $this->description,
            'description_length' => $this->descriptionLength,
            'canonical_url' => $this->canonicalUrl,
            'canonical_mismatch' => $this->canonicalMismatch,
            'robots_meta' => $this->robotsMeta,
            'is_noindex' => $this->isNoindex,
            'h1' => [
                'count' => $this->h1Count,
                'primary' => $this->h1Items[0] ?? null,
                'items' => $this->h1Items,
            ],
            'open_graph' => $this->openGraph,
            'twitter_card' => $this->twitterCard,
            'schema_org' => [
                'present' => $this->schemaBlocksCount > 0 || $this->schemaTypes !== [],
                'blocks_count' => $this->schemaBlocksCount,
                'types' => $this->schemaTypes,
            ],
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
