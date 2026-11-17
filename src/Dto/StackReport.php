<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Technology stack fingerprinting report across CMS, backend, frontend, CDN/WAF, CMP, and tracking.
 */
final readonly class StackReport implements JsonSerializable
{
    /**
     * @param list<string> $backendRuntime
     * @param list<array{name: string, version: ?string, outdated: bool}> $frontendLibraries
     * @param list<string> $cdnWaf
     * @param list<string> $cmpPrivacy
     * @param list<array{name: string, id: ?string}> $trackingAnalytics
     * @param list<array{name: string, source: 'external_cdn'|'local'}> $webFonts
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public string $cmsName,
        public ?string $cmsVersion,
        public string $cmsConfidence,
        public string $webServer,
        public array $backendRuntime,
        public array $frontendLibraries,
        public array $cdnWaf,
        public array $cmpPrivacy,
        public array $trackingAnalytics,
        public array $webFonts,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'cms' => [
                'name' => $this->cmsName,
                'version' => $this->cmsVersion,
                'confidence' => $this->cmsConfidence,
            ],
            'web_server' => $this->webServer,
            'backend_runtime' => $this->backendRuntime,
            'frontend_libraries' => $this->frontendLibraries,
            'cdn_waf' => $this->cdnWaf,
            'cmp_privacy' => $this->cmpPrivacy,
            'tracking_analytics' => $this->trackingAnalytics,
            'web_fonts' => $this->webFonts,
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
