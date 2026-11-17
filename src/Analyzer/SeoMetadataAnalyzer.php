<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Analyzer;

use LeandroPerez\WebInspector\Contract\AnalyzerInterface;
use LeandroPerez\WebInspector\Dto\DiagnosticFinding;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\SeoReport;
use LeandroPerez\WebInspector\Dto\Severity;

/**
 * Extracts and validates On-Page SEO tags, canonical alignment, social cards, and Schema.org JSON-LD.
 */
final class SeoMetadataAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'seo';
    }

    public function analyze(HttpResponse $response): SeoReport
    {
        $xRobots = $response->getHeader('x-robots-tag');

        return $this->analyzeHtml($response->body, $response->effectiveUrl, $xRobots);
    }

    public function analyzeHtml(string $html, string $effectiveUrl, ?string $xRobotsHeader = null): SeoReport
    {
        $title = null;
        if (preg_match('/<title\b[^>]*>(.*?)<\/title>/is', $html, $mTitle) === 1) {
            $decoded = trim(html_entity_decode(strip_tags($mTitle[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            $title = $decoded !== '' ? $decoded : null;
        }

        $description = null;
        if (preg_match('/<meta\b[^>]*\bname=["\']description["\'][^>]*\bcontent=["\']([^"\']*)["\']/i', $html, $mDesc) === 1) {
            $decoded = trim(html_entity_decode($mDesc[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            $description = $decoded !== '' ? $decoded : null;
        } elseif (preg_match('/<meta\b[^>]*\bcontent=["\']([^"\']*)["\'][^>]*\bname=["\']description["\']/i', $html, $mDescAlt) === 1) {
            $decoded = trim(html_entity_decode($mDescAlt[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            $description = $decoded !== '' ? $decoded : null;
        }

        $canonicalUrl = $this->extractCanonical($html, $effectiveUrl);
        $canonicalMismatch = false;
        if ($canonicalUrl !== null && $effectiveUrl !== '') {
            $canonicalMismatch = rtrim(strtolower($canonicalUrl), '/') !== rtrim(strtolower($effectiveUrl), '/');
        }

        $robotsMeta = null;
        if (preg_match('/<meta\b[^>]*\bname=["\']robots["\'][^>]*\bcontent=["\']([^"\']*)["\']/i', $html, $mRobots) === 1) {
            $robotsMeta = trim($mRobots[1]);
        }

        $isNoindex = ($robotsMeta !== null && stripos($robotsMeta, 'noindex') !== false)
            || ($xRobotsHeader !== null && stripos($xRobotsHeader, 'noindex') !== false);

        $h1Items = [];
        if (preg_match_all('/<h1\b[^>]*>(.*?)<\/h1>/is', $html, $mH1) > 0) {
            foreach ($mH1[1] as $rawH1) {
                $clean = trim((string) preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($rawH1), ENT_QUOTES | ENT_HTML5, 'UTF-8')));
                if ($clean !== '') {
                    $h1Items[] = $clean;
                }
            }
        }

        $ogTags = [];
        $twTags = [];
        if (preg_match_all('/<meta\b[^>]*>/i', $html, $mMeta) > 0) {
            foreach ($mMeta[0] as $tag) {
                if (preg_match('/\b(?:property|name)=["\']og:([a-zA-Z0-9_:\-]+)["\']/i', $tag, $mProp) === 1
                    && preg_match('/\bcontent=["\']([^"\']*)["\']/i', $tag, $mCont) === 1
                ) {
                    $key = strtolower(trim($mProp[1]));
                    $val = trim(html_entity_decode($mCont[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                    if ($val !== '' && !isset($ogTags[$key])) {
                        $ogTags[$key] = $val;
                    }
                }

                if (preg_match('/\b(?:name|property)=["\']twitter:([a-zA-Z0-9_:\-]+)["\']/i', $tag, $mTwProp) === 1
                    && preg_match('/\bcontent=["\']([^"\']*)["\']/i', $tag, $mTwCont) === 1
                ) {
                    $key = strtolower(trim($mTwProp[1]));
                    $val = trim(html_entity_decode($mTwCont[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                    if ($val !== '' && !isset($twTags[$key])) {
                        $twTags[$key] = $val;
                    }
                }
            }
        }

        $schemaTypes = [];
        $schemaBlocksCount = 0;
        if (preg_match_all('/<script\b[^>]*\btype=["\']application\/ld\+json["\'][^>]*>(.*?)<\/script>/is', $html, $mSchema) > 0) {
            $schemaBlocksCount = count($mSchema[1]);
            foreach ($mSchema[1] as $rawJson) {
                $decoded = json_decode(trim($rawJson), true);
                if (is_array($decoded)) {
                    $this->collectSchemaTypes($decoded, $schemaTypes);
                }
            }
        }
        $schemaTypes = array_values(array_unique($schemaTypes));

        $findings = [];
        if ($isNoindex) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'seo',
                title: 'Noindex Directive Detected on Page',
                detail: 'Search engines are instructed not to index this URL via meta robots or X-Robots-Tag.',
                recommendation: 'Remove the "noindex" directive if the page is intended to appear in search results.',
            );
        }

        if ($title === null) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'seo',
                title: 'Missing or Empty <title> Tag',
                detail: 'The HTML document lacks a descriptive <title> element.',
                recommendation: 'Add a unique, descriptive <title> tag between 30 and 60 characters.',
            );
        }

        if ($canonicalMismatch) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'seo',
                title: 'Canonical URL Mismatch',
                detail: sprintf('Declared canonical URL (%s) differs from effective URL (%s).', (string) $canonicalUrl, $effectiveUrl),
                recommendation: 'Align rel="canonical" with the final resolved URL to prevent duplicate content signals.',
            );
        }

        $h1Count = count($h1Items);
        if ($h1Count === 0) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Warning,
                category: 'seo',
                title: 'Missing Primary <h1> Heading',
                detail: 'No <h1> heading element was detected on the page.',
                recommendation: 'Include a single semantic <h1> heading describing the primary topic of the page.',
            );
        } elseif ($h1Count > 1) {
            $findings[] = new DiagnosticFinding(
                severity: Severity::Info,
                category: 'seo',
                title: sprintf('Multiple <h1> Headings Detected (%d)', $h1Count),
                detail: 'More than one <h1> element was found in the document markup.',
                recommendation: 'Use a single <h1> for the main title and <h2>-<h6> for subsections.',
            );
        }

        return new SeoReport(
            title: $title,
            titleLength: $title !== null ? mb_strlen($title) : 0,
            description: $description,
            descriptionLength: $description !== null ? mb_strlen($description) : 0,
            canonicalUrl: $canonicalUrl,
            canonicalMismatch: $canonicalMismatch,
            robotsMeta: $robotsMeta,
            isNoindex: $isNoindex,
            h1Count: $h1Count,
            h1Items: $h1Items,
            openGraph: [
                'present' => $ogTags !== [],
                'title' => $ogTags['title'] ?? null,
                'description' => $ogTags['description'] ?? null,
                'image' => $ogTags['image'] ?? $ogTags['image:url'] ?? $ogTags['image:secure_url'] ?? null,
                'type' => $ogTags['type'] ?? null,
                'url' => $ogTags['url'] ?? null,
            ],
            twitterCard: [
                'present' => $twTags !== [],
                'card' => $twTags['card'] ?? null,
                'title' => $twTags['title'] ?? null,
                'image' => $twTags['image'] ?? $twTags['image:src'] ?? null,
            ],
            schemaBlocksCount: $schemaBlocksCount,
            schemaTypes: $schemaTypes,
            findings: $findings,
        );
    }

    private function extractCanonical(string $html, string $effectiveUrl): ?string
    {
        if (preg_match('/<link\b[^>]*\brel=["\']canonical["\'][^>]*\bhref=["\']([^"\']+)["\']/i', $html, $m) !== 1) {
            return null;
        }

        $raw = trim($m[1]);
        if ($raw === '') {
            return null;
        }

        if (str_starts_with($raw, '//')) {
            return 'https:' . $raw;
        }

        if (str_starts_with($raw, '/')) {
            $parts = parse_url($effectiveUrl);
            if (is_array($parts) && isset($parts['scheme'], $parts['host'])) {
                $port = isset($parts['port']) ? ':' . $parts['port'] : '';

                return $parts['scheme'] . '://' . $parts['host'] . $port . $raw;
            }
        }

        return $raw;
    }

    /**
     * @param array<mixed> $node
     * @param list<string> $types
     */
    private function collectSchemaTypes(array $node, array &$types): void
    {
        if (isset($node['@type'])) {
            if (is_string($node['@type']) && trim($node['@type']) !== '') {
                $types[] = trim($node['@type']);
            } elseif (is_array($node['@type'])) {
                foreach ($node['@type'] as $item) {
                    if (is_string($item) && trim($item) !== '') {
                        $types[] = trim($item);
                    }
                }
            }
        }

        foreach ($node as $value) {
            if (is_array($value)) {
                $this->collectSchemaTypes($value, $types);
            }
        }
    }
}
