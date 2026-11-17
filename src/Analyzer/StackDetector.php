<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\Severity;
use LeandroPerez\WebInspector\Dto\StackReport;

/**
 * Fingerprints CMS platforms, backend runtimes, frontend libraries, CDN/WAF, CMP banners, and trackers.
 */
final class StackDetector implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'stack';
    }

    /**
     * @param list<string> $nameservers
     */
    public function analyze(HttpResponse $response, ?string $reverseDns = null, array $nameservers = []): StackReport
    {
        return $this->detect($response->body, $response->headers, $reverseDns, $nameservers);
    }

    /**
     * @param array<string, list<string>> $headers
     * @param list<string> $nameservers
     */
    public function detect(string $html, array $headers, ?string $reverseDns = null, array $nameservers = []): StackReport
    {
        $serverHeader = $headers['server'][0] ?? 'Hidden / Proxy';
        $poweredBy = $headers['x-powered-by'][0] ?? null;
        $cookiesJoined = strtolower(implode(' ', $headers['set-cookie'] ?? []));
        $findings = [];

        // 1. CMS Detection
        [$cmsName, $cmsVersion, $cmsConfidence] = $this->detectCms($html, $headers);

        // 2. Backend Runtime / Frameworks
        $backend = [];
        if ($poweredBy !== null && stripos($poweredBy, 'php') !== false) {
            $backend[] = $poweredBy;
        } elseif (str_contains($cookiesJoined, 'phpsessid') || str_contains($html, '.php')) {
            $backend[] = 'PHP';
        }
        if (str_contains($cookiesJoined, 'laravel_session')) {
            $backend[] = 'Laravel';
        }
        if (isset($headers['x-debug-token']) || str_contains($cookiesJoined, 'sf_redirect')) {
            $backend[] = 'Symfony';
        }
        if ($this->hasHeaderPrefix($headers, 'x-aspnet-') || str_contains($cookiesJoined, 'asp.net_sessionid') || str_contains($html, '__VIEWSTATE')) {
            $backend[] = 'ASP.NET';
        }
        if (($poweredBy !== null && stripos($poweredBy, 'express') !== false) || str_contains($cookiesJoined, 'connect.sid')) {
            $backend[] = 'Node.js / Express';
        }
        if (str_contains($cookiesJoined, 'csrftoken') && str_contains($cookiesJoined, 'sessionid')) {
            $backend[] = 'Python / Django';
        }
        if (str_contains($cookiesJoined, 'jsessionid')) {
            $backend[] = 'Java / Spring';
        }
        if ($backend === []) {
            $backend[] = 'Hidden / Managed';
        }

        // 3. Frontend Frameworks & Libraries (with outdated jQuery detection)
        /** @var list<array{name: string, version: ?string, outdated: bool}> $frontend */
        $frontend = [];
        if (str_contains($html, '__NEXT_DATA__') || str_contains($html, '/_next/static/')) {
            $frontend[] = ['name' => 'Next.js', 'version' => null, 'outdated' => false];
        } elseif (str_contains($html, 'data-reactroot') || str_contains($html, 'react-dom')) {
            $frontend[] = ['name' => 'React', 'version' => null, 'outdated' => false];
        }

        if (str_contains($html, '__NUXT__') || str_contains($html, '/_nuxt/')) {
            $frontend[] = ['name' => 'Nuxt', 'version' => null, 'outdated' => false];
        } elseif (str_contains($html, 'data-v-') || str_contains($html, 'vue.global.js') || str_contains($html, 'vue.min.js')) {
            $frontend[] = ['name' => 'Vue.js', 'version' => null, 'outdated' => false];
        }

        if (str_contains($html, 'ng-version') || str_contains($html, 'ng-app')) {
            $frontend[] = ['name' => 'Angular', 'version' => null, 'outdated' => false];
        }

        $jqVersion = $this->extractJqueryVersion($html);
        if ($jqVersion !== null || str_contains($html, 'jquery.min.js') || str_contains($html, 'jquery.js')) {
            $isOutdated = $jqVersion !== null && version_compare($jqVersion, '3.5.0', '<');
            $frontend[] = ['name' => 'jQuery', 'version' => $jqVersion, 'outdated' => $isOutdated];

            if ($isOutdated) {
                $findings[] = new DiagnosticFinding(
                    severity: Severity::Warning,
                    category: 'security',
                    title: sprintf('Outdated jQuery Library Detected (v%s)', (string) $jqVersion),
                    detail: 'jQuery versions below 3.5.0 contain known DOM XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023).',
                    recommendation: 'Upgrade jQuery to 3.7.x or migrate legacy scripts to vanilla JavaScript.',
                );
            }
        }

        if (str_contains($html, 'bootstrap.min.css') || str_contains($html, 'bootstrap.min.js') || preg_match('/class=["\'][^"\']*\b(?:btn-primary|navbar-expand|container-fluid)\b/', $html) === 1) {
            $frontend[] = ['name' => 'Bootstrap', 'version' => null, 'outdated' => false];
        }
        if (str_contains($html, 'tailwindcss') || preg_match('/class=["\'][^"\']*\b(?:grid-cols-|max-w-7xl|dark:bg-)\b/', $html) === 1) {
            $frontend[] = ['name' => 'Tailwind CSS', 'version' => null, 'outdated' => false];
        }
        if (str_contains($html, 'x-data=') || str_contains($html, 'alpinejs')) {
            $frontend[] = ['name' => 'Alpine.js', 'version' => null, 'outdated' => false];
        }
        if (str_contains($html, 'hx-get=') || str_contains($html, 'htmx.org')) {
            $frontend[] = ['name' => 'HTMX', 'version' => null, 'outdated' => false];
        }

        // 4. CDN / WAF / Reverse Proxy
        $cdn = $this->detectCdnAndWaf($headers, $serverHeader, $reverseDns, $nameservers);

        // 5. CMP Cookie Consent & Tracking
        $cmp = [];
        if (str_contains($html, 'iubenda.com') || str_contains($html, '_iub')) {
            $cmp[] = 'Iubenda';
        }
        if (str_contains($html, 'consent.cookiebot.com') || str_contains($html, 'cookiebot.js')) {
            $cmp[] = 'Cookiebot';
        }
        if (str_contains($html, 'cdn.cookielaw.org') || str_contains($html, 'onetrust')) {
            $cmp[] = 'OneTrust';
        }
        if (str_contains($html, 'complianz') || str_contains($html, 'cmplz_')) {
            $cmp[] = 'Complianz GDPR';
        }
        if (str_contains($html, 'usercentrics.eu')) {
            $cmp[] = 'Usercentrics';
        }
        if (str_contains($html, 'cookieyes.com') || str_contains($html, 'cky-')) {
            $cmp[] = 'CookieYes';
        }

        /** @var list<array{name: string, id: ?string}> $tracking */
        $tracking = [];
        if (preg_match('/\b(G-[A-Z0-9]{8,12})\b/', $html, $mGa4) === 1) {
            $tracking[] = ['name' => 'Google Analytics 4', 'id' => $mGa4[1]];
        }
        if (preg_match('/\b(GTM-[A-Z0-9]{5,10})\b/', $html, $mGtm) === 1) {
            $tracking[] = ['name' => 'Google Tag Manager', 'id' => $mGtm[1]];
        }
        if (str_contains($html, 'connect.facebook.net') || str_contains($html, 'fbq(')) {
            $tracking[] = ['name' => 'Meta Pixel', 'id' => null];
        }
        if (str_contains($html, 'clarity.ms/tag/')) {
            $tracking[] = ['name' => 'Microsoft Clarity', 'id' => null];
        }
        if (str_contains($html, 'static.hotjar.com')) {
            $tracking[] = ['name' => 'Hotjar', 'id' => null];
        }

        // 6. Web Fonts
        /** @var list<array{name: string, source: 'external_cdn'|'local'}> $webFonts */
        $webFonts = [];
        if (str_contains($html, 'fonts.googleapis.com') || str_contains($html, 'fonts.gstatic.com')) {
            $webFonts[] = ['name' => 'Google Fonts', 'source' => 'external_cdn'];
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'privacy',
                title: 'Google Fonts Loaded from External CDN',
                detail: 'Fonts are fetched directly from Google servers, transmitting visitor IP addresses to third-party infrastructure.',
                recommendation: 'Self-host WOFF2 font files locally to eliminate external DNS lookups and improve GDPR compliance.',
            );
        } elseif (preg_match('#/(?:fonts|webfonts)/[^"\'\s>]+\.woff2?#i', $html) === 1) {
            $webFonts[] = ['name' => 'Self-Hosted Web Fonts', 'source' => 'local'];
        }

        return new StackReport(
            cmsName: $cmsName,
            cmsVersion: $cmsVersion,
            cmsConfidence: $cmsConfidence,
            webServer: $serverHeader,
            backendRuntime: $backend,
            frontendLibraries: $frontend,
            cdnWaf: $cdn,
            cmpPrivacy: $cmp,
            trackingAnalytics: $tracking,
            webFonts: $webFonts,
            findings: $findings,
        );
    }

    /**
     * @param array<string, list<string>> $headers
     * @return array{0: string, 1: ?string, 2: string}
     */
    private function detectCms(string $html, array $headers): array
    {
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9.]+)/i', $html, $m) === 1) {
            return ['WordPress', $m[1], 'high'];
        }
        if (str_contains($html, 'wp-content/') || str_contains($html, 'wp-includes/') || str_contains($html, 'api.w.org')) {
            return ['WordPress', null, 'high'];
        }
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!\s+([0-9.]+)/i', $html, $m) === 1) {
            return ['Joomla', $m[1], 'high'];
        }
        if (str_contains($html, '/media/system/js/') || str_contains($html, 'Joomla!')) {
            return ['Joomla', null, 'high'];
        }
        if (str_contains($html, 'Drupal.settings') || str_contains($html, '/sites/default/files/')) {
            return ['Drupal', null, 'high'];
        }
        if (str_contains($html, 'var prestashop =') || str_contains($html, 'prestashop')) {
            return ['PrestaShop', null, 'high'];
        }
        if (str_contains($html, 'Mage.Cookies') || $this->hasHeaderPrefix($headers, 'x-magento-')) {
            return ['Magento / Adobe Commerce', null, 'high'];
        }
        if (str_contains($html, 'cdn.shopify.com') || str_contains($html, 'Shopify.shop')) {
            return ['Shopify', 'Cloud', 'high'];
        }
        if (str_contains($html, 'wixsite.com') || $this->hasHeaderPrefix($headers, 'x-wix-')) {
            return ['Wix', 'Cloud', 'high'];
        }
        if (str_contains($html, 'static1.squarespace.com')) {
            return ['Squarespace', 'Cloud', 'high'];
        }
        if (str_contains($html, 'data-wf-page') || str_contains($html, 'assets.website-files.com')) {
            return ['Webflow', 'Cloud', 'high'];
        }

        return ['Custom / Static', null, 'low'];
    }

    private function extractJqueryVersion(string $html): ?string
    {
        if (preg_match('#/jquery-([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js#i', $html, $m) === 1) {
            return $m[1];
        }
        if (preg_match('#/jquery(?:\.min)?\.js\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)#i', $html, $mVer) === 1) {
            return $mVer[1];
        }

        return null;
    }

    /**
     * @param array<string, list<string>> $headers
     * @param list<string> $nameservers
     * @return list<string>
     */
    private function detectCdnAndWaf(array $headers, string $serverHeader, ?string $reverseDns, array $nameservers): array
    {
        $cdn = [];
        $serverLower = strtolower($serverHeader);

        if ($this->hasHeaderPrefix($headers, 'cf-') || $serverLower === 'cloudflare') {
            $cdn[] = 'Cloudflare';
        }
        if (str_contains($serverLower, 'aruba-proxy') || $this->hasHeaderPrefix($headers, 'x-aruba-')) {
            $cdn[] = 'Aruba Proxy / Cache';
        }
        if ($this->hasHeaderPrefix($headers, 'x-akamai-')) {
            $cdn[] = 'Akamai';
        }
        if ($this->hasHeaderPrefix($headers, 'x-fastly-')) {
            $cdn[] = 'Fastly';
        }
        if ($this->hasHeaderPrefix($headers, 'x-amz-cf-')) {
            $cdn[] = 'AWS CloudFront';
        }
        if ($this->hasHeaderPrefix($headers, 'x-vercel-') || $serverLower === 'vercel') {
            $cdn[] = 'Vercel Edge';
        }
        if ($this->hasHeaderPrefix($headers, 'x-varnish')) {
            $cdn[] = 'Varnish Cache';
        }
        if (str_contains($serverLower, 'litespeed') || $this->hasHeaderPrefix($headers, 'x-litespeed-')) {
            $cdn[] = 'LiteSpeed / LSCache';
        }

        if (!in_array('Cloudflare', $cdn, true)) {
            foreach ($nameservers as $ns) {
                if (str_contains(strtolower($ns), 'cloudflare.com')) {
                    $cdn[] = 'Cloudflare (DNS)';
                    break;
                }
            }
        }

        $ptrLower = strtolower($reverseDns ?? '');
        if ($ptrLower !== '' && (str_contains($ptrLower, 'bunnyinfra.net') || str_contains($ptrLower, 'b-cdn.net'))) {
            $cdn[] = 'BunnyCDN';
        }

        return array_values(array_unique($cdn));
    }

    /**
     * @param array<string, list<string>> $headers
     */
    private function hasHeaderPrefix(array $headers, string $prefix): bool
    {
        $lower = strtolower($prefix);
        foreach (array_keys($headers) as $key) {
            if (str_starts_with(strtolower($key), $lower)) {
                return true;
            }
        }

        return false;
    }
}
