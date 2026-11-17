<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * WordPress-specific audit report covering Core, active Theme, Plugins, and hardening probes.
 */
final readonly class WordPressReport implements JsonSerializable
{
    /**
     * @param list<string> $detectionMethods
     * @param array{detected: bool, name: string, slug: string, version: ?string, author: ?string, is_child: bool, parent_theme: ?string} $theme
     * @param list<array{slug: string, name: string, version: ?string, source: string}> $plugins
     * @param array<string, mixed> $hardening
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public bool $isWordPress,
        public ?string $version,
        public array $detectionMethods,
        public array $theme,
        public array $plugins,
        public array $hardening,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'is_wordpress' => $this->isWordPress,
            'version' => $this->version,
            'version_detected' => $this->version !== null,
            'detection_methods' => $this->detectionMethods,
            'theme' => $this->theme,
            'plugins_count' => count($this->plugins),
            'plugins' => $this->plugins,
            'hardening' => $this->hardening,
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
