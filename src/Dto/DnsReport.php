<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Aggregated DNS, hosting, mail exchanger, and email anti-spoofing report.
 */
final readonly class DnsReport implements JsonSerializable
{
    /**
     * @param list<string> $ipv6Records
     * @param list<string> $nameservers
     * @param list<MxRecord> $mxRecords
     * @param list<string> $caaRecords
     * @param list<DiagnosticFinding> $findings
     */
    public function __construct(
        public ?string $ipv4,
        public ?string $ipv6,
        public array $ipv6Records,
        public ?string $reverseDns,
        public string $hostingProvider,
        public string $apexDomain,
        public array $nameservers,
        public array $mxRecords,
        public string $mailProvider,
        public bool $spfConfigured,
        public ?string $spfRaw,
        public bool $dmarcConfigured,
        public ?string $dmarcPolicy,
        public ?string $dmarcRaw,
        public bool $caaConfigured,
        public array $caaRecords,
        public array $findings,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'ipv4' => $this->ipv4,
            'ipv6' => $this->ipv6,
            'ipv6_records' => $this->ipv6Records,
            'reverse_dns' => $this->reverseDns,
            'hosting_provider' => $this->hostingProvider,
            'apex_domain' => $this->apexDomain,
            'nameservers' => $this->nameservers,
            'mx_records' => array_map(
                static fn(MxRecord $mx): array => $mx->jsonSerialize(),
                $this->mxRecords,
            ),
            'mail_provider' => $this->mailProvider,
            'spf' => [
                'configured' => $this->spfConfigured,
                'raw' => $this->spfRaw,
            ],
            'dmarc' => [
                'configured' => $this->dmarcConfigured,
                'policy' => $this->dmarcPolicy,
                'raw' => $this->dmarcRaw,
            ],
            'caa' => [
                'configured' => $this->caaConfigured,
                'records' => $this->caaRecords,
            ],
            'findings' => array_map(
                static fn(DiagnosticFinding $finding): array => $finding->jsonSerialize(),
                $this->findings,
            ),
        ];
    }
}
