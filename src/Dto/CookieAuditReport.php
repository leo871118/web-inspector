<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Aggregated security posture report for HTTP Set-Cookie headers.
 */
final readonly class CookieAuditReport implements JsonSerializable
{
    /**
     * @param list<CookieItem> $cookies
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public int $totalCount,
        public int $secureCount,
        public int $httpOnlyCount,
        public int $sameSiteCount,
        public int $securityScore,
        public array $cookies,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'total_count' => $this->totalCount,
            'secure_count' => $this->secureCount,
            'httponly_count' => $this->httpOnlyCount,
            'samesite_count' => $this->sameSiteCount,
            'security_score' => $this->securityScore,
            'cookies' => array_map(
                static fn(CookieItem $cookie): array => $cookie->jsonSerialize(),
                $this->cookies,
            ),
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
