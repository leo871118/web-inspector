<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\DnsReport;
use LeandroPerez\WebInspector\Dto\MxRecord;
use LeandroPerez\WebInspector\Dto\Severity;
use LeandroPerez\WebInspector\Http\SafeHttpClient;

/**
 * Resolves DNS records (A, AAAA, PTR, NS, MX, SPF, DMARC, CAA) and identifies hosting/mail providers.
 */
final readonly class DnsNetworkAnalyzer implements AnalyzerInterface
{
    /**
     * Common multi-level public suffixes for registrable apex domain extraction.
     */
    private const array MULTI_PART_TLDS = [
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
        'com.au', 'net.au', 'org.au', 'edu.au',
        'co.nz', 'co.jp', 'com.br', 'com.ar', 'com.mx', 'co.za',
    ];

    public function __construct(
        private ?SafeHttpClient $httpClient = null,
    ) {}

    public function getName(): string
    {
        return 'dns';
    }

    public function analyze(string $host): DnsReport
    {
        $cleanHost = preg_replace('/^www\./i', '', strtolower(trim($host))) ?: strtolower(trim($host));
        $apexDomain = $this->extractApexDomain($cleanHost);
        $isSubdomain = $cleanHost !== $apexDomain;

        $ipv4 = $this->resolveIpv4($host, $cleanHost, $apexDomain, $isSubdomain);
        $reverseDns = null;
        if ($ipv4 !== null) {
            $ptr = @gethostbyaddr($ipv4);
            if (is_string($ptr) && $ptr !== '' && $ptr !== $ipv4) {
                $reverseDns = strtolower(rtrim($ptr, '.'));
            }
        }

        $ipv6Records = $this->resolveIpv6($host, $cleanHost, $apexDomain, $isSubdomain);
        $nameservers = $this->resolveNameservers($cleanHost, $apexDomain, $isSubdomain);
        $mxRecords = $this->resolveMx($cleanHost, $apexDomain, $isSubdomain);

        $primaryMxPtr = null;
        if ($mxRecords !== []) {
            $mxIp = @gethostbyname($mxRecords[0]->host);
            if ($mxIp !== $mxRecords[0]->host && filter_var($mxIp, FILTER_VALIDATE_IP) !== false) {
                $mxPtr = @gethostbyaddr($mxIp);
                if (is_string($mxPtr) && $mxPtr !== $mxIp) {
                    $primaryMxPtr = strtolower($mxPtr);
                }
            }
        }

        $spfRaw = $this->resolveSpf($cleanHost, $apexDomain, $isSubdomain);
        $dmarcRaw = $this->resolveDmarc($cleanHost, $apexDomain, $isSubdomain);
        $caaRecords = $this->resolveCaa($cleanHost, $apexDomain, $isSubdomain);

        return $this->buildReport(
            ipv4: $ipv4,
            ipv6Records: $ipv6Records,
            reverseDns: $reverseDns,
            apexDomain: $apexDomain,
            nameservers: $nameservers,
            mxRecords: $mxRecords,
            primaryMxPtr: $primaryMxPtr,
            spfRaw: $spfRaw,
            dmarcRaw: $dmarcRaw,
            caaRecords: $caaRecords,
        );
    }

    /**
     * Builds a complete DnsReport from resolved record values.
     *
     * @param list<string> $ipv6Records
     * @param list<string> $nameservers
     * @param list<MxRecord> $mxRecords
     * @param list<string> $caaRecords
     */
    public function buildReport(
        ?string $ipv4,
        array $ipv6Records,
        ?string $reverseDns,
        string $apexDomain,
        array $nameservers,
        array $mxRecords,
        ?string $primaryMxPtr,
        ?string $spfRaw,
        ?string $dmarcRaw,
        array $caaRecords,
    ): DnsReport {
        $hostingProvider = $this->detectHostingProvider($ipv4, $reverseDns, $nameservers);
        $mailProvider = $this->detectMailProvider($mxRecords, $primaryMxPtr);

        $spfConfigured = $spfRaw !== null && $spfRaw !== '';
        $dmarcConfigured = $dmarcRaw !== null && $dmarcRaw !== '';
        $dmarcPolicy = null;
        if ($dmarcConfigured && preg_match('/\bp=(none|quarantine|reject)\b/i', $dmarcRaw, $matches) === 1) {
            $dmarcPolicy = strtolower($matches[1]);
        }

        $findings = [];
        if (!$spfConfigured) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'dns',
                title: 'Missing SPF Record (v=spf1)',
                detail: 'No TXT SPF record was found for the domain, increasing email spoofing risk.',
                recommendation: 'Publish a TXT record starting with "v=spf1" authorizing your legitimate mail servers.',
            );
        }

        if (!$dmarcConfigured) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'dns',
                title: 'Missing DMARC Record (_dmarc)',
                detail: 'No DMARC policy record was found under _dmarc.' . $apexDomain . '.',
                recommendation: 'Add a "_dmarc" TXT record starting with "v=DMARC1; p=quarantine;" (or "p=none" for initial monitoring).',
            );
        } elseif ($dmarcPolicy === 'none') {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'dns',
                title: 'DMARC Configured in Monitoring Mode (p=none)',
                detail: 'The DMARC record is set to p=none, which reports anomalies without rejecting spoofed messages.',
                recommendation: 'Gradually enforce policy to "p=quarantine" or "p=reject" once legitimate senders are verified.',
            );
        }

        if ($caaRecords === []) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'dns',
                title: 'No DNS CAA Records Configured',
                detail: 'Certification Authority Authorization (CAA) records are not configured to restrict SSL certificate issuance.',
                recommendation: 'Publish a CAA record (e.g., 0 issue "letsencrypt.org") to authorize specific Certificate Authorities.',
            );
        }

        return new DnsReport(
            ipv4: $ipv4,
            ipv6: $ipv6Records[0] ?? null,
            ipv6Records: $ipv6Records,
            reverseDns: $reverseDns,
            hostingProvider: $hostingProvider,
            apexDomain: $apexDomain,
            nameservers: $nameservers,
            mxRecords: $mxRecords,
            mailProvider: $mailProvider,
            spfConfigured: $spfConfigured,
            spfRaw: $spfRaw,
            dmarcConfigured: $dmarcConfigured,
            dmarcPolicy: $dmarcPolicy,
            dmarcRaw: $dmarcRaw,
            caaConfigured: $caaRecords !== [],
            caaRecords: $caaRecords,
            findings: $findings,
        );
    }

    public function extractApexDomain(string $host): string
    {
        $clean = preg_replace('/^www\./i', '', strtolower(trim($host))) ?: strtolower(trim($host));
        if (filter_var($clean, FILTER_VALIDATE_IP) !== false) {
            return $clean;
        }

        $parts = explode('.', $clean);
        $count = count($parts);
        if ($count <= 2) {
            return $clean;
        }

        $lastTwo = $parts[$count - 2] . '.' . $parts[$count - 1];
        if (in_array($lastTwo, self::MULTI_PART_TLDS, true)) {
            return $parts[$count - 3] . '.' . $lastTwo;
        }

        return $lastTwo;
    }

    /**
     * @param list<string> $nameservers
     */
    public function detectHostingProvider(?string $ip, ?string $reverseDns, array $nameservers = []): string
    {
        $ptr = strtolower($reverseDns ?? '');
        foreach ($nameservers as $ns) {
            if (str_contains(strtolower($ns), 'cloudflare.com')) {
                return 'Cloudflare CDN / Edge';
            }
        }

        return match (true) {
            str_contains($ptr, 'cloudflare') => 'Cloudflare CDN / Edge',
            str_contains($ptr, 'aruba.it'), str_contains($ptr, 'technorail.com'), str_starts_with($ip ?? '', '62.149.'), str_starts_with($ip ?? '', '89.119.') => 'Aruba Hosting / Cloud',
            str_contains($ptr, 'amazonaws.com'), str_contains($ptr, 'awsglobalaccelerator.com') => 'Amazon Web Services (AWS)',
            str_contains($ptr, 'googleusercontent.com'), str_contains($ptr, '1e100.net') => 'Google Cloud Platform (GCP)',
            str_contains($ptr, 'azure.com'), str_contains($ptr, 'cloudapp.net') => 'Microsoft Azure',
            str_contains($ptr, 'hetzner'), str_contains($ptr, 'your-server.de') => 'Hetzner Online',
            str_contains($ptr, 'ovh.net'), str_contains($ptr, 'kimsufi.com') => 'OVHcloud',
            str_contains($ptr, 'digitalocean.com') => 'DigitalOcean',
            str_contains($ptr, 'siteground.com') => 'SiteGround',
            $ptr !== '' => sprintf('Network (%s)', $ptr),
            default => 'Unclassified Hosting / ISP',
        };
    }

    /**
     * @param list<MxRecord> $mxRecords
     */
    public function detectMailProvider(array $mxRecords, ?string $primaryMxPtr = null): string
    {
        if ($mxRecords === []) {
            return 'Not configured (No MX records)';
        }

        $joined = strtolower(implode(' ', array_map(static fn(MxRecord $mx): string => $mx->host, $mxRecords)));
        $ptr = strtolower($primaryMxPtr ?? '');

        return match (true) {
            str_contains($joined, 'google.com'), str_contains($joined, 'googlemail.com'), str_contains($joined, 'aspmx') => 'Google Workspace',
            str_contains($joined, 'outlook.com'), str_contains($joined, 'protection.outlook.com') => 'Microsoft 365 / Exchange Online',
            str_contains($joined, 'aruba.it'), str_contains($joined, 'technorail.com'), str_contains($ptr, 'aruba'), str_contains($ptr, 'technorail') => 'Aruba Mail',
            str_contains($joined, 'zoho.com'), str_contains($joined, 'zoho.eu') => 'Zoho Mail',
            str_contains($joined, 'protonmail.ch'), str_contains($joined, 'proton.me') => 'Proton Mail',
            str_contains($joined, 'ovh.net') => 'OVHcloud Mail',
            default => sprintf('Custom Mail Server (%s)', $mxRecords[0]->host),
        };
    }

    private function resolveIpv4(string $host, string $cleanHost, string $apexDomain, bool $isSubdomain): ?string
    {
        foreach (array_unique([$host, $cleanHost, $isSubdomain ? $apexDomain : $cleanHost]) as $candidate) {
            $ip = @gethostbyname($candidate);
            if ($ip !== $candidate && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $ip;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function resolveIpv6(string $host, string $cleanHost, string $apexDomain, bool $isSubdomain): array
    {
        $records = @dns_get_record($host, DNS_AAAA) ?: [];
        if ($records === [] && $cleanHost !== $host) {
            $records = @dns_get_record($cleanHost, DNS_AAAA) ?: [];
        }
        if ($records === [] && $isSubdomain) {
            $records = @dns_get_record($apexDomain, DNS_AAAA) ?: [];
        }

        $ips = [];
        foreach ($records as $record) {
            if (!empty($record['ipv6']) && is_string($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * @return list<string>
     */
    private function resolveNameservers(string $cleanHost, string $apexDomain, bool $isSubdomain): array
    {
        $records = @dns_get_record($cleanHost, DNS_NS) ?: [];
        if ($records === [] && $isSubdomain) {
            $records = @dns_get_record($apexDomain, DNS_NS) ?: [];
        }

        $ns = [];
        foreach ($records as $record) {
            if (!empty($record['target']) && is_string($record['target'])) {
                $ns[] = strtolower(rtrim($record['target'], '.'));
            }
        }

        $ns = array_values(array_unique($ns));
        sort($ns);

        return $ns;
    }

    /**
     * @return list<MxRecord>
     */
    private function resolveMx(string $cleanHost, string $apexDomain, bool $isSubdomain): array
    {
        $records = @dns_get_record($cleanHost, DNS_MX) ?: [];
        if ($records === [] && $isSubdomain) {
            $records = @dns_get_record($apexDomain, DNS_MX) ?: [];
        }

        $mxList = [];
        foreach ($records as $record) {
            if (!empty($record['target']) && is_string($record['target'])) {
                $mxList[] = new MxRecord(
                    host: strtolower(rtrim($record['target'], '.')),
                    priority: is_int($record['pri'] ?? null) ? $record['pri'] : 10,
                );
            }
        }

        usort($mxList, static fn(MxRecord $a, MxRecord $b): int => $a->priority <=> $b->priority);

        return $mxList;
    }

    private function resolveSpf(string $cleanHost, string $apexDomain, bool $isSubdomain): ?string
    {
        $candidates = $isSubdomain ? [$cleanHost, $apexDomain] : [$cleanHost];
        foreach ($candidates as $domain) {
            $records = @dns_get_record($domain, DNS_TXT) ?: [];
            foreach ($records as $record) {
                $txt = is_string($record['txt'] ?? null) ? $record['txt'] : '';
                if (stripos(trim($txt), 'v=spf1') === 0) {
                    return trim($txt);
                }
            }
        }

        return null;
    }

    private function resolveDmarc(string $cleanHost, string $apexDomain, bool $isSubdomain): ?string
    {
        $candidates = $isSubdomain ? ['_dmarc.' . $cleanHost, '_dmarc.' . $apexDomain] : ['_dmarc.' . $cleanHost];
        foreach ($candidates as $domain) {
            $records = @dns_get_record($domain, DNS_TXT) ?: [];
            foreach ($records as $record) {
                $txt = is_string($record['txt'] ?? null) ? $record['txt'] : '';
                if (stripos(trim($txt), 'v=DMARC1') === 0) {
                    return trim($txt);
                }
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function resolveCaa(string $cleanHost, string $apexDomain, bool $isSubdomain): array
    {
        $caa = [];
        $candidates = $isSubdomain ? [$cleanHost, $apexDomain] : [$cleanHost];

        if (defined('DNS_CAA')) {
            $dnsCaaType = (int) constant('DNS_CAA');
            foreach ($candidates as $domain) {
                $records = @dns_get_record($domain, $dnsCaaType) ?: [];
                foreach ($records as $record) {
                    if (is_string($record['tag'] ?? null) && is_string($record['value'] ?? null)) {
                        $flags = is_int($record['flags'] ?? null) ? $record['flags'] : 0;
                        $caa[] = sprintf('%d %s "%s"', $flags, $record['tag'], $record['value']);
                    }
                }
                if ($caa !== []) {
                    break;
                }
            }
        }

        if ($caa === [] && $this->httpClient !== null) {
            foreach ($candidates as $domain) {
                try {
                    $dohUrl = 'https://dns.google/resolve?name=' . rawurlencode($domain) . '&type=CAA';
                    $resp = $this->httpClient->get($dohUrl, 2.0, 1, ['Accept' => 'application/dns-json']);
                    if ($resp->statusCode === 200) {
                        $decoded = json_decode($resp->body, true);
                        if (is_array($decoded) && is_array($decoded['Answer'] ?? null)) {
                            foreach ($decoded['Answer'] as $answer) {
                                if (is_array($answer) && ($answer['type'] ?? 0) === 257 && is_string($answer['data'] ?? null)) {
                                    $caa[] = trim($answer['data']);
                                }
                            }
                        }
                    }
                } catch (\Throwable) {
                    // Ignore DoH fallback errors
                }

                if ($caa !== []) {
                    break;
                }
            }
        }

        return array_values(array_unique($caa));
    }
}
