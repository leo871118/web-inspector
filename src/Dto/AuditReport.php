<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Complete aggregated technical audit report returned by WebInspector.
 */
final readonly class AuditReport implements JsonSerializable
{
    public function __construct(
        public string $target,
        public string $effectiveUrl,
        public int $statusCode,
        public int $responseTimeMs,
        public ?string $protocolVersion,
        public SecurityHeadersReport $securityHeaders,
        public CookieAuditReport $cookies,
        public SslReport $ssl,
        public DnsReport $dns,
        public SeoReport $seo,
        public DomPerformanceReport $domPerformance,
        public StackReport $stack,
        public WordPressReport $wordpress,
        public string $inspectedAt,
    ) {}

    /**
     * Returns all diagnostic findings sorted by severity (Error -> Warning -> Info).
     *
     * @return list<DiagnosticFinding>
     */
    public function getAllFindings(): array
    {
        $all = array_merge(
            $this->securityHeaders->findings,
            $this->cookies->findings,
            $this->ssl->findings,
            $this->dns->findings,
            $this->seo->findings,
            $this->domPerformance->findings,
            $this->stack->findings,
            $this->wordpress->findings,
        );

        usort($all, static fn(DiagnosticFinding $a, DiagnosticFinding $b): int => self::severityRank($a->severity) <=> self::severityRank($b->severity));

        return $all;
    }

    /**
     * @return array{errors: int, warnings: int, info: int, total: int}
     */
    public function getSummary(): array
    {
        $errors = 0;
        $warnings = 0;
        $info = 0;

        foreach ($this->getAllFindings() as $finding) {
            match ($finding->severity) {
                Severity::Error => $errors++,
                Severity::Warning => $warnings++,
                Severity::Info => $info++,
            };
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'info' => $info,
            'total' => $errors + $warnings + $info,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'target' => $this->target,
            'effective_url' => $this->effectiveUrl,
            'status_code' => $this->statusCode,
            'response_time_ms' => $this->responseTimeMs,
            'protocol_version' => $this->protocolVersion,
            'inspected_at' => $this->inspectedAt,
            'summary' => $this->getSummary(),
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->getAllFindings(),
            ),
            'security_headers' => $this->securityHeaders->jsonSerialize(),
            'cookies' => $this->cookies->jsonSerialize(),
            'ssl' => $this->ssl->jsonSerialize(),
            'dns' => $this->dns->jsonSerialize(),
            'seo' => $this->seo->jsonSerialize(),
            'dom_performance' => $this->domPerformance->jsonSerialize(),
            'stack' => $this->stack->jsonSerialize(),
            'wordpress' => $this->wordpress->jsonSerialize(),
        ];
    }

    private static function severityRank(Severity $severity): int
    {
        return match ($severity) {
            Severity::Error => 0,
            Severity::Warning => 1,
            Severity::Info => 2,
        };
    }
}
