<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Contract;

use LeandroPerez\WebInspector\Dto\AuditReport;

/**
 * Contract for optional AI adapters generating executive summaries from an AuditReport.
 */
interface AiSummarizerInterface
{
    public function summarize(AuditReport $report, string $language = 'en'): string;
}
