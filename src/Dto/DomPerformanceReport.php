<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Metrics and security findings for HTML payload size, DOM assets, third-party hosts, and mixed content.
 */
final readonly class DomPerformanceReport implements JsonSerializable
{
    /**
     * @param list<array{host: string, count: int}> $thirdPartyHosts
     * @param list<string> $activeMixedContentUrls
     * @param list<string> $passiveMixedContentUrls
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public float $htmlSizeKb,
        public int $scriptsTotal,
        public int $scriptsExternal,
        public int $stylesCount,
        public int $imagesTotal,
        public int $imagesWithoutLazy,
        public array $thirdPartyHosts,
        public array $activeMixedContentUrls,
        public array $passiveMixedContentUrls,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'html_size_kb' => $this->htmlSizeKb,
            'scripts_total' => $this->scriptsTotal,
            'scripts_external' => $this->scriptsExternal,
            'styles_count' => $this->stylesCount,
            'images_total' => $this->imagesTotal,
            'images_without_lazy' => $this->imagesWithoutLazy,
            'third_party_hosts_count' => count($this->thirdPartyHosts),
            'third_party_hosts' => $this->thirdPartyHosts,
            'mixed_content' => [
                'active_count' => count($this->activeMixedContentUrls),
                'passive_count' => count($this->passiveMixedContentUrls),
                'active_urls' => $this->activeMixedContentUrls,
                'passive_urls' => $this->passiveMixedContentUrls,
            ],
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
