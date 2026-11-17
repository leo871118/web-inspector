<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\Severity;
use LeandroPerez\WebInspector\Dto\SslReport;

/**
 * Inspects TLS/SSL X.509 peer certificates over port 443.
 */
final readonly class SslCertificateAnalyzer implements AnalyzerInterface
{
    public function __construct(
        private float $socketTimeout = 4.0,
    ) {}

    public function getName(): string
    {
        return 'ssl';
    }

    public function analyze(string $host, bool $isHttps): SslReport
    {
        if (!$isHttps) {
            return new SslReport(
                enabled: false,
                valid: false,
                expired: false,
                issuer: null,
                subject: null,
                validFrom: null,
                validTo: null,
                daysRemaining: 0,
                sanDomains: [],
                findings: [
                    new DiagnosticFinding(
                        severity: Severity::Error,
                        category: 'ssl',
                        title: 'HTTPS Not Enabled',
                        detail: 'The target website is served over unencrypted HTTP without TLS encryption.',
                        recommendation: 'Install a valid TLS certificate and redirect all HTTP traffic to HTTPS.',
                    ),
                ],
            );
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client(
            sprintf('ssl://%s:443', $host),
            $errno,
            $errstr,
            $this->socketTimeout,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($stream === false) {
            return new SslReport(
                enabled: true,
                valid: false,
                expired: false,
                issuer: null,
                subject: null,
                validFrom: null,
                validTo: null,
                daysRemaining: 0,
                sanDomains: [],
                findings: [
                    new DiagnosticFinding(
                        severity: Severity::Error,
                        category: 'ssl',
                        title: 'Unable to Read SSL/TLS Peer Certificate',
                        detail: sprintf('TLS handshake on port 443 failed (%s).', $errstr !== '' ? $errstr : 'connection error'),
                        recommendation: 'Verify that port 443 is reachable and configured with a valid certificate chain.',
                    ),
                ],
            );
        }

        $params = stream_context_get_params($stream);
        fclose($stream);

        $peerCert = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$peerCert instanceof \OpenSSLCertificate) {
            return new SslReport(
                enabled: true,
                valid: false,
                expired: false,
                issuer: null,
                subject: null,
                validFrom: null,
                validTo: null,
                daysRemaining: 0,
                sanDomains: [],
                findings: [
                    new DiagnosticFinding(
                        severity: Severity::Error,
                        category: 'ssl',
                        title: 'Missing Peer X.509 Certificate',
                        detail: 'The TLS endpoint did not present an X.509 certificate during handshake.',
                    ),
                ],
            );
        }

        $parsed = openssl_x509_parse($peerCert);
        if (!is_array($parsed)) {
            return new SslReport(
                enabled: true,
                valid: false,
                expired: false,
                issuer: null,
                subject: null,
                validFrom: null,
                validTo: null,
                daysRemaining: 0,
                sanDomains: [],
                findings: [
                    new DiagnosticFinding(
                        severity: Severity::Error,
                        category: 'ssl',
                        title: 'Malformed X.509 Certificate',
                        detail: 'OpenSSL failed to parse the peer certificate structure.',
                    ),
                ],
            );
        }

        return $this->analyzeParsedCertificate($parsed);
    }

    /**
     * Parses an openssl_x509_parse() structure into a typed SslReport.
     *
     * @param array<string, mixed> $parsed
     */
    public function analyzeParsedCertificate(array $parsed, ?int $referenceTimestamp = null): SslReport
    {
        $now = $referenceTimestamp ?? time();
        $validFromTs = is_int($parsed['validFrom_time_t'] ?? null) ? $parsed['validFrom_time_t'] : 0;
        $validToTs = is_int($parsed['validTo_time_t'] ?? null) ? $parsed['validTo_time_t'] : 0;

        $validFrom = $validFromTs > 0 ? gmdate('Y-m-d', $validFromTs) : null;
        $validTo = $validToTs > 0 ? gmdate('Y-m-d', $validToTs) : null;
        $daysRemaining = max(0, (int) floor(($validToTs - $now) / 86400));
        $isValid = $validFromTs > 0 && $now >= $validFromTs && $now <= $validToTs;
        $isExpired = !$isValid || $daysRemaining <= 0;

        $issuerData = is_array($parsed['issuer'] ?? null) ? $parsed['issuer'] : [];
        $issuer = is_string($issuerData['O'] ?? null) && $issuerData['O'] !== ''
            ? $issuerData['O']
            : (is_string($issuerData['CN'] ?? null) && $issuerData['CN'] !== '' ? $issuerData['CN'] : 'Unknown');

        $subjectData = is_array($parsed['subject'] ?? null) ? $parsed['subject'] : [];
        $subject = is_string($subjectData['CN'] ?? null) && $subjectData['CN'] !== '' ? $subjectData['CN'] : null;

        $sanDomains = [];
        $extensions = is_array($parsed['extensions'] ?? null) ? $parsed['extensions'] : [];
        $rawSan = is_string($extensions['subjectAltName'] ?? null) ? $extensions['subjectAltName'] : '';
        if ($rawSan !== '') {
            foreach (explode(',', $rawSan) as $entry) {
                $trimmed = trim($entry);
                if (stripos($trimmed, 'DNS:') === 0) {
                    $domain = trim(substr($trimmed, 4));
                    if ($domain !== '') {
                        $sanDomains[] = $domain;
                    }
                }
            }
            $sanDomains = array_slice(array_values(array_unique($sanDomains)), 0, 20);
        }

        $findings = [];
        if (!$isValid) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Error,
                category: 'ssl',
                title: 'SSL/TLS Certificate Expired or Not Yet Valid',
                detail: sprintf('Certificate issued by %s is valid from %s to %s.', $issuer, $validFrom ?? 'N/A', $validTo ?? 'N/A'),
                recommendation: 'Renew and deploy a valid TLS certificate immediately.',
            );
        } elseif ($daysRemaining <= 15) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'ssl',
                title: sprintf('SSL/TLS Certificate Expiring Soon (%d Days Left)', $daysRemaining),
                detail: sprintf('The certificate issued by %s expires on %s.', $issuer, $validTo ?? 'N/A'),
                recommendation: 'Renew the certificate or verify automated ACME/Certbot renewal.',
            );
        }

        return new SslReport(
            enabled: true,
            valid: $isValid,
            expired: $isExpired,
            issuer: $issuer,
            subject: $subject,
            validFrom: $validFrom,
            validTo: $validTo,
            daysRemaining: $daysRemaining,
            sanDomains: $sanDomains,
            findings: $findings,
        );
    }
}
