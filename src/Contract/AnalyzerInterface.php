<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Contract;

/**
 * Contract implemented by every modular technical analyzer.
 */
interface AnalyzerInterface
{
    /**
     * Unique machine-readable key for this analyzer (e.g. "ssl", "dns", "security_headers").
     */
    public function getName(): string;
}