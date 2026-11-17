<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\DomPerformanceReport;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\Severity;

/**
 * Analyzes HTML payload size, asset counts, image lazy-loading, third-party domains, and mixed content.
 */
final class DomPerformanceAnalyzer implements AnalyzerInterface
{
    private const array IGNORED_HOSTS = [
        'w.org',
        'schema.org',
        'xmlns.com',
        'w3.org',
        'gmpg.org',
        'wordpress.org',
    ];

    public function getName(): string
    {
        return 'dom_performance';
    }

    public function analyze(HttpResponse $response): DomPerformanceReport
    {
        return $this->analyzeHtml($response->body, $response->effectiveUrl);
    }

    public function analyzeHtml(string $html, string $effectiveUrl): DomPerformanceReport
    {
        $htmlSizeKb = round(strlen($html) / 1024, 1);
        $isHttps = str_starts_with(strtolower($effectiveUrl), 'https://');
        $originHost = strtolower((string) parse_url($effectiveUrl, PHP_URL_HOST));
        $cleanOriginHost = preg_replace('/^www\./i', '', $originHost) ?: $originHost;

        $scriptsTotal = 0;
        $scriptsExternal = 0;
        if (preg_match_all('/<script\b([^>]*)>/i', $html, $mScripts) > 0) {
            $scriptsTotal = count($mScripts[0]);
            foreach ($mScripts[1] as $attrs) {
                if (preg_match('/\bsrc=["\'][^"\']+["\']/i', $attrs) === 1) {
                    $scriptsExternal++;
                }
            }
        }

        $stylesCount = 0;
        if (preg_match_all('/<link\b[^>]*\brel=["\']stylesheet["\'][^>]*>/i', $html, $mStyles) > 0) {
            $stylesCount = count($mStyles[0]);
        }

        $imagesTotal = 0;
        $imagesWithoutLazy = 0;
        if (preg_match_all('/<img\b([^>]*)>/i', $html, $mImages) > 0) {
            $imagesTotal = count($mImages[0]);
            foreach ($mImages[1] as $attrs) {
                if (preg_match('/\bloading=["\']lazy["\']/i', $attrs) !== 1) {
                    $imagesWithoutLazy++;
                }
            }
        }

        /** @var array<string, int> $hostCounts */
        $hostCounts = [];
        if (preg_match_all('/\b(?:src|href)=["\'](https?:\/\/[^"\'\s>]+|\/\/[^"\'\s>]+)["\']/i', $html, $mUrls) > 0) {
            foreach ($mUrls[1] as $rawUrl) {
                $normalized = str_starts_with($rawUrl, '//') ? 'https:' . $rawUrl : $rawUrl;
                $parsedHost = parse_url($normalized, PHP_URL_HOST);
                if (!is_string($parsedHost) || $parsedHost === '') {
                    continue;
                }
                $cleanHost = strtolower(preg_replace('/^www\./i', '', $parsedHost) ?: $parsedHost);
                if ($cleanHost === $cleanOriginHost || str_ends_with($cleanHost, '.' . $cleanOriginHost)) {
                    continue;
                }
                if (in_array($cleanHost, self::IGNORED_HOSTS, true) || !str_contains($cleanHost, '.')) {
                    continue;
                }
                $hostCounts[$cleanHost] = ($hostCounts[$cleanHost] ?? 0) + 1;
            }
        }

        arsort($hostCounts);
        $thirdPartyHosts = [];
        foreach (array_slice($hostCounts, 0, 20, true) as $host => $count) {
            $thirdPartyHosts[] = ['host' => $host, 'count' => $count];
        }

        $activeMixed = [];
        $passiveMixed = [];
        if ($isHttps) {
            if (preg_match_all('/<(?:script|link|iframe)\b[^>]*(?:src|href)=["\'](http:\/\/[^"\']+)["\']/i', $html, $mActive) > 0) {
                $activeMixed = array_values(array_unique($mActive[1]));
            }
            if (preg_match_all('/<(?:img|audio|video|source)\b[^>]*(?:src|srcset)=["\'](http:\/\/[^"\']+)["\']/i', $html, $mPassive) > 0) {
                $passiveMixed = array_values(array_unique($mPassive[1]));
            }
        }

        $findings = [];
        if ($activeMixed !== []) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Error,
                category: 'security',
                title: sprintf('Active Mixed Content Detected (%d Resource(s))', count($activeMixed)),
                detail: sprintf('HTTPS page loads scripts, stylesheets, or iframes over insecure HTTP (e.g., %s).', $activeMixed[0]),
                recommendation: 'Upgrade all embedded active resource URLs to HTTPS.',
            );
        }

        if ($passiveMixed !== []) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'security',
                title: sprintf('Passive Mixed Content Detected (%d Asset(s))', count($passiveMixed)),
                detail: sprintf('HTTPS page loads images or media over insecure HTTP (e.g., %s).', $passiveMixed[0]),
                recommendation: 'Serve all media assets over HTTPS to avoid browser security warnings.',
            );
        }

        if ($htmlSizeKb > 300.0) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'performance',
                title: sprintf('Large Initial HTML Payload (%.1f KB)', $htmlSizeKb),
                detail: 'The raw HTML document exceeds 300 KB, increasing download time and DOM parsing overhead.',
                recommendation: 'Reduce inline DOM bloat, excessive page-builder wrappers, or large inline JSON blobs.',
            );
        }

        if ($imagesTotal > 6 && $imagesWithoutLazy > 6) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'performance',
                title: sprintf('%d Images Missing loading="lazy"', $imagesWithoutLazy),
                detail: sprintf('%d out of %d images lack native lazy-loading attributes.', $imagesWithoutLazy, $imagesTotal),
                recommendation: 'Add loading="lazy" to below-the-fold images while keeping above-the-fold LCP images eager.',
            );
        }

        return new DomPerformanceReport(
            htmlSizeKb: $htmlSizeKb,
            scriptsTotal: $scriptsTotal,
            scriptsExternal: $scriptsExternal,
            stylesCount: $stylesCount,
            imagesTotal: $imagesTotal,
            imagesWithoutLazy: $imagesWithoutLazy,
            thirdPartyHosts: $thirdPartyHosts,
            activeMixedContentUrls: $activeMixed,
            passiveMixedContentUrls: $passiveMixed,
            findings: $findings,
        );
    }
}
