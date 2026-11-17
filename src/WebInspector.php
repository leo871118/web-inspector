<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector;

use DateTimeImmutable;
use DateTimeInterface;
use LeandroPerez\WebInspector\Analyzer\CookieAuditAnalyzer;
use LeandroPerez\WebInspector\Analyzer\DnsNetworkAnalyzer;
use LeandroPerez\WebInspector\Analyzer\DomPerformanceAnalyzer;
use LeandroPerez\WebInspector\Analyzer\SecurityHeadersAnalyzer;
use LeandroPerez\WebInspector\Analyzer\SeoMetadataAnalyzer;
use LeandroPerez\WebInspector\Analyzer\SslCertificateAnalyzer;
use LeandroPerez\WebInspector\Analyzer\StackDetector;
use LeandroPerez\WebInspector\Analyzer\WordPressAnalyzer;
use LeandroPerez\WebInspector\Config\InspectorConfig;
use LeandroPerez\WebInspector\Dto\AuditReport;
use LeandroPerez\WebInspector\Dto\DnsReport;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\SslReport;
use LeandroPerez\WebInspector\Dto\WordPressReport;
use LeandroPerez\WebInspector\Exception\InspectorException;
use LeandroPerez\WebInspector\Http\SafeHttpClient;
use LeandroPerez\WebInspector\Http\UrlNormalizer;

/**
 * Main entry point orchestrating HTTP fetching and modular technical website analyzers.
 */
final readonly class WebInspector
{
    private SafeHttpClient $httpClient;
    private UrlNormalizer $urlNormalizer;
    private SecurityHeadersAnalyzer $securityHeadersAnalyzer;
    private CookieAuditAnalyzer $cookieAuditAnalyzer;
    private SslCertificateAnalyzer $sslAnalyzer;
    private DnsNetworkAnalyzer $dnsAnalyzer;
    private SeoMetadataAnalyzer $seoAnalyzer;
    private DomPerformanceAnalyzer $domPerformanceAnalyzer;
    private StackDetector $stackDetector;
    private WordPressAnalyzer $wordPressAnalyzer;

    public function __construct(
        private InspectorConfig $config = new InspectorConfig(),
        ?SafeHttpClient $httpClient = null,
        ?UrlNormalizer $urlNormalizer = null,
        ?SecurityHeadersAnalyzer $securityHeadersAnalyzer = null,
        ?CookieAuditAnalyzer $cookieAuditAnalyzer = null,
        ?SslCertificateAnalyzer $sslAnalyzer = null,
        ?DnsNetworkAnalyzer $dnsAnalyzer = null,
        ?SeoMetadataAnalyzer $seoAnalyzer = null,
        ?DomPerformanceAnalyzer $domPerformanceAnalyzer = null,
        ?StackDetector $stackDetector = null,
        ?WordPressAnalyzer $wordPressAnalyzer = null,
    ) {
        $this->urlNormalizer = $urlNormalizer ?? new UrlNormalizer();
        $this->httpClient = $httpClient ?? new SafeHttpClient($this->config, $this->urlNormalizer);
        $this->securityHeadersAnalyzer = $securityHeadersAnalyzer ?? new SecurityHeadersAnalyzer();
        $this->cookieAuditAnalyzer = $cookieAuditAnalyzer ?? new CookieAuditAnalyzer();
        $this->sslAnalyzer = $sslAnalyzer ?? new SslCertificateAnalyzer($this->config->probeTimeout);
        $this->dnsAnalyzer = $dnsAnalyzer ?? new DnsNetworkAnalyzer($this->httpClient);
        $this->seoAnalyzer = $seoAnalyzer ?? new SeoMetadataAnalyzer();
        $this->domPerformanceAnalyzer = $domPerformanceAnalyzer ?? new DomPerformanceAnalyzer();
        $this->stackDetector = $stackDetector ?? new StackDetector();
        $this->wordPressAnalyzer = $wordPressAnalyzer ?? new WordPressAnalyzer($this->config);
    }

    /**
     * Performs a complete technical audit on a domain or URL.
     */
    public function inspect(string $rawTarget): AuditReport
    {
        $normalized = $this->urlNormalizer->normalize($rawTarget);
        $targetUrl = $normalized['url'];
        $host = $normalized['host'];
        $scheme = $normalized['scheme'];

        $response = $this->fetchWithHttpFallback($rawTarget, $targetUrl, $host, $scheme);

        $effectiveHost = (string) (parse_url($response->effectiveUrl, PHP_URL_HOST) ?: $host);
        $isHttps = str_starts_with(strtolower($response->effectiveUrl), 'https://');

        $dnsReport = $this->dnsAnalyzer->analyze($effectiveHost);
        $sslReport = $this->sslAnalyzer->analyze($effectiveHost, $isHttps);
        $wpReport = $this->wordPressAnalyzer->inspect($this->httpClient, $response);

        return $this->assembleReport($targetUrl, $response, $dnsReport, $sslReport, $wpReport);
    }

    /**
     * Assembles an AuditReport from pre-collected HTTP, DNS, SSL, and WordPress data.
     */
    public function assembleReport(
        string $targetUrl,
        HttpResponse $response,
        DnsReport $dnsReport,
        SslReport $sslReport,
        WordPressReport $wpReport,
    ): AuditReport {
        $headersReport = $this->securityHeadersAnalyzer->analyze($response);
        $cookiesReport = $this->cookieAuditAnalyzer->analyze($response);
        $seoReport = $this->seoAnalyzer->analyze($response);
        $domReport = $this->domPerformanceAnalyzer->analyze($response);
        $stackReport = $this->stackDetector->analyze($response, $dnsReport->reverseDns, $dnsReport->nameservers);

        return new AuditReport(
            target: $targetUrl,
            effectiveUrl: $response->effectiveUrl,
            statusCode: $response->statusCode,
            responseTimeMs: $response->durationMs,
            protocolVersion: $response->protocolVersion,
            securityHeaders: $headersReport,
            cookies: $cookiesReport,
            ssl: $sslReport,
            dns: $dnsReport,
            seo: $seoReport,
            domPerformance: $domReport,
            stack: $stackReport,
            wordpress: $wpReport,
            inspectedAt: (new DateTimeImmutable())->format(DateTimeInterface::ATOM),
        );
    }

    private function fetchWithHttpFallback(string $rawTarget, string $targetUrl, string $host, string $scheme): HttpResponse
    {
        $explicitScheme = preg_match('#^https?://#i', trim($rawTarget)) === 1;

        try {
            return $this->httpClient->get($targetUrl);
        } catch (InspectorException $primaryException) {
            if ($scheme !== 'https' || $explicitScheme) {
                throw $primaryException;
            }

            return $this->httpClient->get('http://' . $host . '/');
        }
    }
}
