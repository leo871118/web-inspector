<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Http;

use LeandroPerez\WebInspector\Config\InspectorConfig;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Exception\InspectorException;

/**
 * Native PHP cURL HTTP client configured with IPv4 preference, redirect tracking, and SSRF checks.
 */
final readonly class SafeHttpClient
{
    public function __construct(
        private InspectorConfig $config = new InspectorConfig(),
        private UrlNormalizer $urlNormalizer = new UrlNormalizer(),
    ) {}

    /**
     * Executes an HTTP GET request.
     *
     * @param array<string, string> $headers
     */
    public function get(
        string $url,
        ?float $timeout = null,
        ?int $maxRedirects = null,
        array $headers = [],
    ): HttpResponse {
        return $this->request('GET', $url, null, $timeout, $maxRedirects, $headers);
    }

    /**
     * Executes an HTTP POST request with a JSON payload over HTTP/1.1.
     *
     * @param array<string, mixed> $payload
     * @param array<string, string> $headers
     */
    public function postJson(
        string $url,
        array $payload,
        ?float $timeout = null,
        array $headers = [],
    ): HttpResponse {
        $jsonBody = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $mergedHeaders = array_merge([
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'Expect' => '',
        ], $headers);

        return $this->request('POST', $url, $jsonBody, $timeout, 0, $mergedHeaders, true);
    }

    /**
     * @param array<string, string> $headers
     */
    private function request(
        string $method,
        string $url,
        ?string $body,
        ?float $timeout,
        ?int $maxRedirects,
        array $headers,
        bool $forceHttp11 = false,
    ): HttpResponse {
        $host = (string) parse_url($url, PHP_URL_HOST);
        if ($this->config->blockPrivateNetworks && $host !== '') {
            $this->urlNormalizer->assertPublicHost($host);
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new InspectorException('Failed to initialize cURL session.');
        }

        $effectiveTimeout = $timeout ?? $this->config->defaultTimeout;
        $effectiveRedirects = $maxRedirects ?? $this->config->maxRedirects;

        $defaultHeaders = [
            'User-Agent' => $this->config->userAgent,
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.9,*/*;q=0.8',
            'Accept-Language' => 'en-US,en;q=0.9,it;q=0.8',
        ];

        $formattedHeaders = [];
        foreach (array_merge($defaultHeaders, $headers) as $name => $value) {
            $formattedHeaders[] = $value === '' ? "{$name}:" : "{$name}: {$value}";
        }

        /** @var list<string> $rawHeaderLines */
        $rawHeaderLines = [];
        /** @var list<string> $rawCookies */
        $rawCookies = [];
        /** @var list<int> $statusHistory */
        $statusHistory = [];

        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => $effectiveRedirects > 0,
            CURLOPT_MAXREDIRS => $effectiveRedirects,
            CURLOPT_TIMEOUT_MS => (int) round($effectiveTimeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) round(min($effectiveTimeout, 5.0) * 1000),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ENCODING => '',
            CURLOPT_HTTPHEADER => $formattedHeaders,
            CURLOPT_HEADERFUNCTION => static function (\CurlHandle $handle, string $headerLine) use (&$rawHeaderLines, &$rawCookies, &$statusHistory): int {
                $length = strlen($headerLine);
                $trimmed = trim($headerLine);
                if ($trimmed === '') {
                    return $length;
                }

                if (preg_match('#^HTTP/[0-9.]+\s+([0-9]{3})#i', $trimmed, $matches)) {
                    $statusHistory[] = (int) $matches[1];
                    $rawHeaderLines = [];
                    $rawCookies = [];

                    return $length;
                }

                $rawHeaderLines[] = $trimmed;
                if (stripos($trimmed, 'set-cookie:') === 0) {
                    $rawCookies[] = trim(substr($trimmed, 11));
                }

                return $length;
            },
        ];

        if ($method === 'POST') {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $body ?? '';
        }

        if (defined('CURLOPT_IPRESOLVE') && defined('CURL_IPRESOLVE_V4')) {
            $options[CURLOPT_IPRESOLVE] = CURL_IPRESOLVE_V4;
        }

        if ($forceHttp11 && defined('CURL_HTTP_VERSION_1_1')) {
            $options[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
        }

        if ($this->config->httpProxy !== null && $this->config->httpProxy !== '') {
            $options[CURLOPT_PROXY] = $this->config->httpProxy;
        }

        curl_setopt_array($ch, $options);

        $startTime = microtime(true);
        $responseBody = curl_exec($ch);
        $durationMs = (int) round((microtime(true) - $startTime) * 1000);

        $curlError = curl_error($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $effectiveUrl = (string) (curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: $url);
        $redirectCount = (int) curl_getinfo($ch, CURLINFO_REDIRECT_COUNT);
        $rawHttpVersion = (int) curl_getinfo($ch, CURLINFO_HTTP_VERSION);
        unset($ch);

        if ($responseBody === false && $curlError !== '') {
            throw new InspectorException(sprintf('HTTP request to "%s" failed: %s', $url, $curlError));
        }

        $finalHost = (string) parse_url($effectiveUrl, PHP_URL_HOST);
        if ($this->config->blockPrivateNetworks && $finalHost !== '' && $finalHost !== $host) {
            $this->urlNormalizer->assertPublicHost($finalHost);
        }

        $parsedHeaders = [];
        foreach ($rawHeaderLines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $key = strtolower(trim($parts[0]));
                $parsedHeaders[$key][] = trim($parts[1]);
            }
        }

        $protocolVersion = match ($rawHttpVersion) {
            CURL_HTTP_VERSION_1_0 => 'HTTP/1.0',
            CURL_HTTP_VERSION_1_1 => 'HTTP/1.1',
            CURL_HTTP_VERSION_2_0, CURL_HTTP_VERSION_2TLS, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE => 'HTTP/2',
            30 => 'HTTP/3',
            default => null,
        };

        return new HttpResponse(
            statusCode: $statusCode,
            initialStatusCode: $statusHistory[0] ?? $statusCode,
            effectiveUrl: $effectiveUrl,
            body: is_string($responseBody) ? $responseBody : '',
            headers: $parsedHeaders,
            rawCookies: $rawCookies,
            redirectCount: $redirectCount,
            durationMs: $durationMs,
            protocolVersion: $protocolVersion,
        );
    }
}
