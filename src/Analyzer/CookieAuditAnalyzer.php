<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\CookieAuditReport;
use LeandroPerez\WebInspector\Dto\CookieItem;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\Severity;

/**
 * Audits Set-Cookie headers for Secure, HttpOnly, and SameSite security attributes.
 */
final class CookieAuditAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'cookies';
    }

    public function analyze(HttpResponse $response): CookieAuditReport
    {
        $isHttps = str_starts_with(strtolower($response->effectiveUrl), 'https://');

        return $this->analyzeRawCookies($response->rawCookies, $isHttps);
    }

    /**
     * @param list<string> $rawCookies
     */
    public function analyzeRawCookies(array $rawCookies, bool $isHttps): CookieAuditReport
    {
        $cookies = [];
        $secureCount = 0;
        $httpOnlyCount = 0;
        $sameSiteCount = 0;
        $sameSiteNoneWithoutSecure = 0;

        foreach ($rawCookies as $rawHeader) {
            $parts = explode(';', $rawHeader);
            $nameValue = explode('=', trim($parts[0]), 2);
            $name = trim($nameValue[0]);
            if ($name === '') {
                continue;
            }

            $rawValue = trim($nameValue[1] ?? '');
            $maskedValue = strlen($rawValue) > 6 ? substr($rawValue, 0, 3) . '***' : '***';

            $secure = false;
            $httpOnly = false;
            $sameSite = null;
            $expires = null;
            $maxAge = null;
            $domain = null;
            $path = '/';

            $partCount = count($parts);
            for ($i = 1; $i < $partCount; $i++) {
                $attr = trim($parts[$i]);
                if ($attr === '') {
                    continue;
                }

                if (strcasecmp($attr, 'secure') === 0) {
                    $secure = true;
                } elseif (strcasecmp($attr, 'httponly') === 0) {
                    $httpOnly = true;
                } elseif (stripos($attr, 'samesite=') === 0) {
                    $sameSite = ucfirst(strtolower(trim(substr($attr, 9))));
                } elseif (stripos($attr, 'expires=') === 0) {
                    $expires = trim(substr($attr, 8));
                } elseif (stripos($attr, 'max-age=') === 0) {
                    $maxAge = (int) trim(substr($attr, 8));
                } elseif (stripos($attr, 'domain=') === 0) {
                    $domain = trim(substr($attr, 7));
                } elseif (stripos($attr, 'path=') === 0) {
                    $path = trim(substr($attr, 5));
                }
            }

            if ($secure) {
                $secureCount++;
            }
            if ($httpOnly) {
                $httpOnlyCount++;
            }
            if ($sameSite !== null && $sameSite !== '') {
                $sameSiteCount++;
                if (strcasecmp($sameSite, 'None') === 0 && !$secure) {
                    $sameSiteNoneWithoutSecure++;
                }
            }

            $cookies[] = new CookieItem(
                name: $name,
                maskedValue: $maskedValue,
                secure: $secure,
                httpOnly: $httpOnly,
                sameSite: $sameSite,
                expires: $expires,
                maxAge: $maxAge,
                domain: $domain,
                path: $path,
            );
        }

        $total = count($cookies);
        $findings = [];

        if ($total > 0) {
            $missingSecure = $total - $secureCount;
            if ($isHttps && $missingSecure > 0) {
                $findings[] = new DiagnosticFinding(
                    severity: Severity::Warning,
                    category: 'cookies',
                    title: sprintf('%d Cookie(s) Missing "Secure" Flag on HTTPS', $missingSecure),
                    detail: 'Cookies without the Secure attribute may be transmitted over unencrypted HTTP connections.',
                    recommendation: 'Add the "Secure" flag to all cookies served over HTTPS.',
                );
            }

            $missingHttpOnly = $total - $httpOnlyCount;
            if ($missingHttpOnly > 0) {
                $findings[] = new DiagnosticFinding(
                    severity: Severity::Info,
                    category: 'cookies',
                    title: sprintf('%d Cookie(s) Missing "HttpOnly" Flag', $missingHttpOnly),
                    detail: 'Cookies without HttpOnly are accessible via document.cookie in JavaScript, increasing XSS session hijacking impact.',
                    recommendation: 'Set the "HttpOnly" attribute on session and authentication cookies.',
                );
            }

            if ($sameSiteNoneWithoutSecure > 0) {
                $findings[] = new DiagnosticFinding(
                    severity: Severity::Warning,
                    category: 'cookies',
                    title: sprintf('%d Cookie(s) Set "SameSite=None" Without "Secure"', $sameSiteNoneWithoutSecure),
                    detail: 'Modern browsers reject cookies configured with SameSite=None unless the Secure attribute is also present.',
                    recommendation: 'Add the "Secure" flag alongside "SameSite=None".',
                );
            }
        }

        $securityScore = 100;
        if ($total > 0) {
            $penalty = 0;
            if ($isHttps) {
                $penalty += (int) round((($total - $secureCount) / $total) * 40);
            }
            $penalty += (int) round((($total - $httpOnlyCount) / $total) * 35);
            $penalty += (int) round((($total - $sameSiteCount) / $total) * 25);
            $securityScore = max(0, 100 - $penalty);
        }

        return new CookieAuditReport(
            totalCount: $total,
            secureCount: $secureCount,
            httpOnlyCount: $httpOnlyCount,
            sameSiteCount: $sameSiteCount,
            securityScore: $securityScore,
            cookies: $cookies,
            findings: $findings,
        );
    }
}
