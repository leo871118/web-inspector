<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Immutable inspection report for an X.509 SSL/TLS certificate.
 */
final readonly class SslReport implements JsonSerializable
{
    /**
     * @param list<string> $sanDomains
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public bool $enabled,
        public bool $valid,
        public bool $expired,
        public ?string $issuer,
        public ?string $subject,
        public ?string $validFrom,
        public ?string $validTo,
        public int $daysRemaining,
        public array $sanDomains,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'enabled' => $this->enabled,
            'valid' => $this->valid,
            'expired' => $this->expired,
            'issuer' => $this->issuer,
            'subject' => $this->subject,
            'valid_from' => $this->validFrom,
            'valid_to' => $this->validTo,
            'days_remaining' => $this->daysRemaining,
            'san_domains' => $this->sanDomains,
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
