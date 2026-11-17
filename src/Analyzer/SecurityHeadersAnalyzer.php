<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\HeaderCheckResult;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\SecurityHeadersReport;
use LeandroPerez\WebInspector\Dto\Severity;

/**
 * Evaluates HTTP security headers and computes a normalized 0-100 score and letter grade.
 */
final class SecurityHeadersAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'security_headers';
    }

    public function analyze(HttpResponse $response): SecurityHeadersReport
    {
        $isHttps = str_starts_with(strtolower($response->effectiveUrl), 'https://');
        $findings = [];
        $score = 0;

        // 1. Strict-Transport-Security (25 pts)
        $hstsVal = $response->getHeader('strict-transport-security');
        $hstsPresent = $hstsVal !== null && trim($hstsVal) !== '';
        $hstsMaxAge = null;
        if ($hstsPresent && preg_match('/max-age=(\d+)/i', $hstsVal, $matches) === 1) {
            $hstsMaxAge = (int) $matches[1];
        }
        if ($hstsPresent) {
            $score += 25;
        } elseif ($isHttps) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'security',
                title: 'Missing Strict-Transport-Security (HSTS) Header',
                detail: 'The server does not enforce HTTPS via HSTS, leaving initial connections vulnerable to protocol downgrade attacks.',
                recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" on HTTPS responses.',
            );
        }

        // 2. Content-Security-Policy (25 pts enforced, 10 pts report-only)
        $cspEnforced = $response->getHeader('content-security-policy');
        $cspReportOnly = $response->getHeader('content-security-policy-report-only');
        $cspPresent = ($cspEnforced !== null && trim($cspEnforced) !== '')
            || ($cspReportOnly !== null && trim($cspReportOnly) !== '');
        $isReportOnly = ($cspEnforced === null || trim($cspEnforced) === '') && $cspPresent;
        $cspVal = $isReportOnly ? $cspReportOnly : $cspEnforced;

        if ($cspPresent) {
            $score += $isReportOnly ? 10 : 25;
        } else {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'security',
                title: 'Missing Content-Security-Policy (CSP)',
                detail: 'No Content-Security-Policy header was detected to restrict script, style, and frame sources.',
                recommendation: 'Define a Content-Security-Policy header to mitigate Cross-Site Scripting (XSS) and data injection risks.',
            );
        }

        // 3. X-Frame-Options (20 pts)
        $xfoVal = $response->getHeader('x-frame-options');
        $xfoValid = $xfoVal !== null && in_array(strtoupper(trim($xfoVal)), ['DENY', 'SAMEORIGIN'], true);
        if ($xfoValid) {
            $score += 20;
        } else {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'security',
                title: 'Missing or Weak X-Frame-Options Header',
                detail: 'The response does not restrict framing with DENY or SAMEORIGIN, exposing pages to clickjacking.',
                recommendation: 'Set "X-Frame-Options: SAMEORIGIN" (or "DENY") and complement with CSP frame-ancestors.',
            );
        }

        // 4. X-Content-Type-Options (15 pts)
        $xctoVal = $response->getHeader('x-content-type-options');
        $xctoValid = $xctoVal !== null && strtolower(trim($xctoVal)) === 'nosniff';
        if ($xctoValid) {
            $score += 15;
        } else {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'security',
                title: 'Missing X-Content-Type-Options: nosniff',
                detail: 'Browsers are not instructed to disable MIME-type sniffing on served assets.',
                recommendation: 'Configure "X-Content-Type-Options: nosniff" at the web server or CDN level.',
            );
        }

        // 5. Referrer-Policy (10 pts)
        $rpVal = $response->getHeader('referrer-policy');
        $rpPresent = $rpVal !== null && trim($rpVal) !== '';
        if ($rpPresent) {
            $score += 10;
        }

        // 6. Permissions-Policy (5 pts)
        $ppVal = $response->getHeader('permissions-policy') ?? $response->getHeader('feature-policy');
        $ppPresent = $ppVal !== null && trim($ppVal) !== '';
        if ($ppPresent) {
            $score += 5;
        }

        $grade = match (true) {
            $score >= 90 => 'A+',
            $score >= 80 => 'A',
            $score >= 65 => 'B',
            $score >= 50 => 'C',
            $score >= 30 => 'D',
            default => 'F',
        };

        $headers = [
            'hsts' => new HeaderCheckResult(
                present: $hstsPresent,
                value: $hstsVal,
                meta: [
                    'max_age' => $hstsMaxAge,
                    'include_subdomains' => $hstsPresent && stripos($hstsVal, 'includesubdomains') !== false,
                    'preload' => $hstsPresent && stripos($hstsVal, 'preload') !== false,
                ],
            ),
            'csp' => new HeaderCheckResult(
                present: $cspPresent,
                value: $cspVal,
                meta: ['report_only' => $isReportOnly],
            ),
            'x_frame_options' => new HeaderCheckResult(
                present: $xfoValid,
                value: $xfoVal,
            ),
            'x_content_type_options' => new HeaderCheckResult(
                present: $xctoValid,
                value: $xctoVal,
            ),
            'referrer_policy' => new HeaderCheckResult(
                present: $rpPresent,
                value: $rpVal,
            ),
            'permissions_policy' => new HeaderCheckResult(
                present: $ppPresent,
                value: $ppVal,
            ),
        ];

        return new SecurityHeadersReport(
            score: $score,
            grade: $grade,
            headers: $headers,
            findings: $findings,
        );
    }
}
