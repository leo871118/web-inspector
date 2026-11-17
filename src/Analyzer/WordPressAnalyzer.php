<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Config\InspectorConfig;
use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\Severity;
use LeandroPerez\WebInspector\Dto\WordPressReport;
use LeandroPerez\WebInspector\Http\SafeHttpClient;

/**
 * Audits WordPress installations for core version, active theme, plugins, and security hardening.
 */
final readonly class WordPressAnalyzer implements AnalyzerInterface
{
    private const array CORE_NAMESPACES = [
        'wp/v2',
        'wp/v1',
        'oembed/1.0',
        'wp-site-health/v1',
        'wp-block-editor/v1',
    ];

    public function __construct(
        private InspectorConfig $config = new InspectorConfig(),
    ) {}

    public function getName(): string
    {
        return 'wordpress';
    }

    public function inspect(SafeHttpClient $client, HttpResponse $homepage): WordPressReport
    {
        $html = $homepage->body;
        $methods = $this->detectPassiveSignals($html);

        $parts = parse_url($homepage->effectiveUrl);
        $baseOrigin = '';
        if (is_array($parts) && isset($parts['scheme'], $parts['host'])) {
            $port = isset($parts['port']) ? ':' . $parts['port'] : '';
            $baseOrigin = $parts['scheme'] . '://' . $parts['host'] . $port;
        }

        $restResponse = null;
        $usersResponse = null;
        $xmlrpcResponse = null;
        $authorEnumResponse = null;
        $debugLogResponse = null;
        $installResponse = null;
        $themeStyleBody = null;

        if ($baseOrigin !== '') {
            if ($methods === []) {
                $restResponse = $this->safeProbe($client, $baseOrigin . '/wp-json/');
                if ($restResponse !== null && $restResponse->statusCode === 200 && str_contains($restResponse->body, 'wp/v2')) {
                    $methods[] = 'rest-api';
                }
            }

            if ($methods !== []) {
                if ($restResponse === null) {
                    $restResponse = $this->safeProbe($client, $baseOrigin . '/wp-json/');
                }
                $usersResponse = $this->safeProbe($client, $baseOrigin . '/wp-json/wp/v2/users?per_page=10');
                $xmlrpcResponse = $this->safeProbe($client, $baseOrigin . '/xmlrpc.php');
                $authorEnumResponse = $this->safeProbe($client, $baseOrigin . '/?author=1', 0);
                $debugLogResponse = $this->safeProbe($client, $baseOrigin . '/wp-content/debug.log');
                $installResponse = $this->safeProbe($client, $baseOrigin . '/wp-admin/install.php');

                $themeSlug = $this->extractThemeSlug($html);
                if ($themeSlug !== '') {
                    $styleResp = $this->safeProbe($client, $baseOrigin . '/wp-content/themes/' . rawurlencode($themeSlug) . '/style.css');
                    if ($styleResp !== null && $styleResp->statusCode === 200) {
                        $themeStyleBody = $styleResp->body;
                    }
                }
            }
        }

        return $this->analyzeFromResponses(
            html: $html,
            restResponse: $restResponse,
            usersResponse: $usersResponse,
            xmlrpcResponse: $xmlrpcResponse,
            authorEnumResponse: $authorEnumResponse,
            debugLogResponse: $debugLogResponse,
            installResponse: $installResponse,
            themeStyleBody: $themeStyleBody,
        );
    }

    /**
     * Pure deterministic analysis method suitable for offline unit testing.
     */
    public function analyzeFromResponses(
        string $html,
        ?HttpResponse $restResponse = null,
        ?HttpResponse $usersResponse = null,
        ?HttpResponse $xmlrpcResponse = null,
        ?HttpResponse $authorEnumResponse = null,
        ?HttpResponse $debugLogResponse = null,
        ?HttpResponse $installResponse = null,
        ?string $themeStyleBody = null,
    ): WordPressReport {
        $methods = $this->detectPassiveSignals($html);
        if ($restResponse !== null && $restResponse->statusCode === 200 && str_contains($restResponse->body, 'wp/v2')) {
            $methods[] = 'rest-api';
        }
        $methods = array_values(array_unique($methods));

        if ($methods === []) {
            return new WordPressReport(
                isWordPress: false,
                version: null,
                detectionMethods: [],
                theme: [
                    'detected' => false,
                    'name' => 'N/A',
                    'slug' => '',
                    'version' => null,
                    'author' => null,
                    'is_child' => false,
                    'parent_theme' => null,
                ],
                plugins: [],
                hardening: [],
                findings: [],
            );
        }

        $version = $this->extractCoreVersion($html);
        $theme = $this->analyzeTheme($html, $themeStyleBody);
        $plugins = $this->extractPlugins($html, $restResponse);

        $findings = [];
        $hardening = [];

        // 1. REST API Users Exposure
        $usersExposed = false;
        /** @var list<string> $usernames */
        $usernames = [];
        if ($usersResponse !== null && $usersResponse->statusCode === 200) {
            $decodedUsers = json_decode($usersResponse->body, true);
            if (is_array($decodedUsers)) {
                foreach ($decodedUsers as $user) {
                    if (is_array($user) && is_string($user['slug'] ?? null) && $user['slug'] !== '') {
                        $usernames[] = $user['slug'];
                    }
                }
            }
            if ($usernames !== []) {
                $usersExposed = true;
                $findings[] = new DiagnosticFinding(
                    severity: Severity::Warning,
                    category: 'security',
                    title: sprintf('REST API User Enumeration Exposed (%d Account(s))', count($usernames)),
                    detail: sprintf('Endpoint /wp-json/wp/v2/users publicly exposes usernames: %s.', implode(', ', array_slice($usernames, 0, 5))),
                    recommendation: 'Restrict unauthenticated access to /wp/v2/users via authentication or a security plugin.',
                );
            }
        }
        $hardening['rest_users_exposed'] = $usersExposed;
        $hardening['rest_usernames'] = $usernames;

        // 2. Author Enumeration (?author=1)
        $authorEnumExposed = false;
        $exposedAuthor = null;
        if ($authorEnumResponse !== null) {
            $location = $authorEnumResponse->getHeader('location') ?? '';
            if (in_array($authorEnumResponse->statusCode, [301, 302, 307, 308], true)
                && preg_match('#/author/([a-zA-Z0-9_.\-]+)/?#i', $location, $mAuthor) === 1
            ) {
                $authorEnumExposed = true;
                $exposedAuthor = $mAuthor[1];
            } elseif ($authorEnumResponse->statusCode === 200
                && preg_match('/class=["\'][^"\']*\bauthor-([a-zA-Z0-9_.\-]+)\b/i', $authorEnumResponse->body, $mBodyAuthor) === 1
            ) {
                $authorEnumExposed = true;
                $exposedAuthor = $mBodyAuthor[1];
            }
        }
        if ($authorEnumExposed) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'security',
                title: 'Author Enumeration via /?author=1',
                detail: sprintf('Author slug "%s" can be enumerated via /?author=1.', (string) $exposedAuthor),
                recommendation: 'Block author archive enumeration queries or redirect /?author=N to the homepage.',
            );
        }
        $hardening['author_enum_exposed'] = $authorEnumExposed;
        $hardening['exposed_author'] = $exposedAuthor;

        // 3. XML-RPC Endpoint
        $xmlrpcActive = $xmlrpcResponse !== null
            && in_array($xmlrpcResponse->statusCode, [200, 405], true)
            && str_contains($xmlrpcResponse->body, 'XML-RPC server accepts POST requests only');
        if ($xmlrpcActive) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'security',
                title: 'XML-RPC Endpoint Enabled (/xmlrpc.php)',
                detail: 'xmlrpc.php is publicly reachable and increases brute-force amplification surface.',
                recommendation: 'Disable XML-RPC at the web server or security layer unless required by Jetpack or mobile apps.',
            );
        }
        $hardening['xmlrpc_active'] = $xmlrpcActive;

        // 4. Public debug.log
        $debugLogExposed = $debugLogResponse !== null
            && $debugLogResponse->statusCode === 200
            && strlen($debugLogResponse->body) > 10
            && !str_contains(strtolower($debugLogResponse->body), '<html')
            && (str_contains($debugLogResponse->body, 'PHP') || str_contains($debugLogResponse->body, 'Stack trace'));
        if ($debugLogExposed) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Error,
                category: 'security',
                title: 'Publicly Accessible WordPress debug.log',
                detail: '/wp-content/debug.log is downloadable and may leak file paths, SQL queries, or credentials.',
                recommendation: 'Delete /wp-content/debug.log, block access in Nginx/Apache, and set WP_DEBUG_LOG outside webroot.',
            );
        }
        $hardening['debug_log_exposed'] = $debugLogExposed;

        // 5. Exposed install.php
        $installExposed = $installResponse !== null
            && $installResponse->statusCode === 200
            && !str_contains(strtolower($installResponse->body), 'already installed')
            && str_contains(strtolower($installResponse->body), 'setup-config.php');
        if ($installExposed) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Error,
                category: 'security',
                title: 'Unconfigured WordPress Installer Accessible (/wp-admin/install.php)',
                detail: 'The installation wizard is reachable by unauthenticated visitors.',
                recommendation: 'Complete installation or restrict access to /wp-admin/install.php immediately.',
            );
        }
        $hardening['install_php_exposed'] = $installExposed;

        return new WordPressReport(
            isWordPress: true,
            version: $version,
            detectionMethods: $methods,
            theme: $theme,
            plugins: $plugins,
            hardening: $hardening,
            findings: $findings,
        );
    }

    /**
     * @return list<string>
     */
    private function detectPassiveSignals(string $html): array
    {
        $methods = [];
        if (str_contains($html, 'wp-content/')) {
            $methods[] = 'wp-content';
        }
        if (str_contains($html, 'wp-includes/')) {
            $methods[] = 'wp-includes';
        }
        if (str_contains($html, 'api.w.org')) {
            $methods[] = 'rest-link';
        }
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress/i', $html) === 1) {
            $methods[] = 'meta-generator';
        }

        return $methods;
    }

    private function extractCoreVersion(string $html): ?string
    {
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i', $html, $m) === 1) {
            return $m[1];
        }

        $assetPatterns = [
            '#wp-emoji-release\.min\.js\?(?:[^"\'\s>]*&)?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)#i',
            '#dashicons(?:\.min)?\.css\?(?:[^"\'\s>]*&)?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)#i',
            '#block-library/style(?:\.min)?\.css\?(?:[^"\'\s>]*&)?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)#i',
        ];
        foreach ($assetPatterns as $pattern) {
            if (preg_match($pattern, $html, $mVer) === 1) {
                return $mVer[1];
            }
        }

        return null;
    }

    private function extractThemeSlug(string $html): string
    {
        if (preg_match_all('~/wp-content/themes/([a-zA-Z0-9_-]+)/[^"\'\s>]+~i', $html, $matches) > 0) {
            foreach ($matches[1] as $slug) {
                if (!in_array($slug, ['plugins', 'uploads', 'cache'], true)) {
                    return $slug;
                }
            }
        }

        return '';
    }

    /**
     * @return array{detected: bool, name: string, slug: string, version: ?string, author: ?string, is_child: bool, parent_theme: ?string}
     */
    private function analyzeTheme(string $html, ?string $styleCssBody): array
    {
        $slug = $this->extractThemeSlug($html);
        if ($slug === '') {
            return [
                'detected' => false,
                'name' => 'Undetected',
                'slug' => '',
                'version' => null,
                'author' => null,
                'is_child' => false,
                'parent_theme' => null,
            ];
        }

        $name = ucwords(str_replace(['-', '_'], ' ', $slug));
        $version = null;
        if (preg_match('~/wp-content/themes/' . preg_quote($slug, '~') . '/[^"\'\s>]*[?&]ver=([0-9a-zA-Z._-]+)~i', $html, $mVer) === 1) {
            $version = $mVer[1];
        }
        $author = null;
        $parentTheme = null;
        $isChild = false;

        if ($styleCssBody !== null && $styleCssBody !== '') {
            $header = substr($styleCssBody, 0, 4096);
            if (preg_match('/Theme Name:\s*([^\r\n]+)/i', $header, $mName) === 1) {
                $name = trim($mName[1]);
            }
            if (preg_match('/Version:\s*([^\r\n]+)/i', $header, $mStyleVer) === 1) {
                $version = trim($mStyleVer[1]);
            }
            if (preg_match('/Author:\s*([^\r\n]+)/i', $header, $mAuthor) === 1) {
                $author = trim($mAuthor[1]);
            }
            if (preg_match('/Template:\s*([a-zA-Z0-9_-]+)/i', $header, $mTemplate) === 1) {
                $parentTheme = trim($mTemplate[1]);
                $isChild = true;
            }
        }

        return [
            'detected' => true,
            'name' => $name,
            'slug' => $slug,
            'version' => $version,
            'author' => $author,
            'is_child' => $isChild,
            'parent_theme' => $parentTheme,
        ];
    }

    /**
     * @return list<array{slug: string, name: string, version: ?string, source: string}>
     */
    private function extractPlugins(string $html, ?HttpResponse $restResponse): array
    {
        /** @var array<string, array{slug: string, name: string, version: ?string, source: string}> $plugins */
        $plugins = [];

        if (preg_match_all('~/wp-content/plugins/([a-zA-Z0-9_-]+)/([^"\'\s>]+)~i', $html, $matches, PREG_SET_ORDER) > 0) {
            foreach ($matches as $match) {
                $slug = strtolower(trim($match[1]));
                if ($slug === '' || in_array($slug, ['themes', 'uploads', 'mu-plugins'], true)) {
                    continue;
                }
                $ver = null;
                if (preg_match('/[?&]ver=([0-9a-zA-Z._-]+)/i', $match[2], $mVer) === 1) {
                    $ver = $mVer[1];
                }

                if (!isset($plugins[$slug])) {
                    $plugins[$slug] = [
                        'slug' => $slug,
                        'name' => ucwords(str_replace(['-', '_'], ' ', $slug)),
                        'version' => $ver,
                        'source' => 'Asset HTML',
                    ];
                } elseif ($ver !== null && $plugins[$slug]['version'] === null) {
                    $plugins[$slug]['version'] = $ver;
                }
            }
        }

        if ($restResponse !== null && $restResponse->statusCode === 200) {
            $decoded = json_decode($restResponse->body, true);
            if (is_array($decoded) && is_array($decoded['namespaces'] ?? null)) {
                foreach ($decoded['namespaces'] as $ns) {
                    if (!is_string($ns)) {
                        continue;
                    }
                    $lower = strtolower(trim($ns));
                    if ($lower === '' || in_array($lower, self::CORE_NAMESPACES, true) || str_starts_with($lower, 'wp/')) {
                        continue;
                    }
                    $base = explode('/', $lower)[0];
                    $slug = (string) preg_replace('/[^a-z0-9_-]/', '', $base);
                    if ($slug === '') {
                        continue;
                    }
                    if (isset($plugins[$slug])) {
                        $plugins[$slug]['source'] = 'Asset + REST API';
                    } else {
                        $plugins[$slug] = [
                            'slug' => $slug,
                            'name' => ucwords(str_replace(['-', '_'], ' ', $slug)),
                            'version' => null,
                            'source' => 'REST API',
                        ];
                    }
                }
            }
        }

        ksort($plugins);

        return array_values($plugins);
    }

    private function safeProbe(SafeHttpClient $client, string $url, int $maxRedirects = 2): ?HttpResponse
    {
        if ($this->config->requestPauseMicroseconds > 0) {
            usleep($this->config->requestPauseMicroseconds);
        }

        try {
            return $client->get($url, $this->config->probeTimeout, $maxRedirects);
        } catch (\Throwable) {
            return null;
        }
    }
}
