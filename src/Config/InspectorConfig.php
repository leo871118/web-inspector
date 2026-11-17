<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Config;

/**
 * Immutable configuration object for HTTP requests, timeouts, and SSRF protection.
 */
final readonly class InspectorConfig
{
    public function __construct(
        public float $defaultTimeout = 8.0,
        public float $probeTimeout = 4.0,
        public int $maxRedirects = 5,
        public int $requestPauseMicroseconds = 250_000,
        public string $userAgent = 'Mozilla/5.0 (compatible; WebInspectorPHP/1.0; +https://github.com/leandroperez/web-inspector)',
        public bool $blockPrivateNetworks = true,
        public ?string $httpProxy = null,
    ) {}
}
