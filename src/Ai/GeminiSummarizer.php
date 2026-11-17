<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Ai;

use LeandroPerez\WebInspector\Contract\AiSummarizerInterface;
use LeandroPerez\WebInspector\Dto\AuditReport;
use LeandroPerez\WebInspector\Exception\InspectorException;
use LeandroPerez\WebInspector\Http\SafeHttpClient;

/**
 * Optional Google Gemini adapter that summarizes an AuditReport over IPv4 / HTTP-1.1.
 */
final readonly class GeminiSummarizer implements AiSummarizerInterface
{
    public function __construct(
        private string $apiKey,
        private string $model = 'gemini-2.5-flash',
        private SafeHttpClient $httpClient = new SafeHttpClient(),
        private float $timeout = 30.0,
    ) {}

    public function summarize(AuditReport $report, string $language = 'en'): string
    {
        if (trim($this->apiKey) === '') {
            throw new InspectorException('Google Gemini API key cannot be empty.');
        }

        $compactPayload = [
            'target' => $report->effectiveUrl,
            'status_code' => $report->statusCode,
            'response_time_ms' => $report->responseTimeMs,
            'protocol' => $report->protocolVersion,
            'summary' => $report->getSummary(),
            'security_headers' => [
                'score' => $report->securityHeaders->score,
                'grade' => $report->securityHeaders->grade,
            ],
            'cookies_score' => $report->cookies->securityScore,
            'ssl' => [
                'valid' => $report->ssl->valid,
                'days_remaining' => $report->ssl->daysRemaining,
                'issuer' => $report->ssl->issuer,
            ],
            'dns' => [
                'hosting' => $report->dns->hostingProvider,
                'mail' => $report->dns->mailProvider,
                'spf' => $report->dns->spfConfigured,
                'dmarc' => $report->dns->dmarcPolicy ?? ($report->dns->dmarcConfigured ? 'configured' : 'missing'),
                'caa' => $report->dns->caaConfigured,
            ],
            'stack' => [
                'cms' => $report->stack->cmsName,
                'cms_version' => $report->stack->cmsVersion,
                'cdn' => $report->stack->cdnWaf,
            ],
            'wordpress' => [
                'is_wordpress' => $report->wordpress->isWordPress,
                'version' => $report->wordpress->version,
                'plugins_count' => count($report->wordpress->plugins),
            ],
            'findings' => array_slice($report->jsonSerialize()['findings'], 0, 15),
        ];

        $prompt = sprintf(
            "You are a Senior Web Infrastructure & Security Engineer. Analyze the following technical website audit JSON and produce a concise, actionable operational summary in language '%s' structured in 3 bulleted sections: 1. Infrastructure & Performance, 2. Security & Hardening Risks, 3. Priority Action Plan.\n\nAUDIT DATA:\n%s",
            $language,
            json_encode($compactPayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        );

        $endpoint = sprintf(
            'https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent',
            rawurlencode($this->model),
        );

        $response = $this->httpClient->postJson(
            url: $endpoint,
            payload: [
                'contents' => [
                    [
                        'role' => 'user',
                        'parts' => [['text' => $prompt]],
                    ],
                ],
                'generationConfig' => [
                    'temperature' => 0.2,
                    'maxOutputTokens' => 1200,
                ],
            ],
            timeout: $this->timeout,
            headers: ['x-goog-api-key' => $this->apiKey],
        );

        $decoded = json_decode($response->body, true);
        if ($response->statusCode !== 200 || !is_array($decoded)) {
            $errMsg = is_array($decoded) && is_string($decoded['error']['message'] ?? null)
                ? $decoded['error']['message']
                : sprintf('HTTP %d', $response->statusCode);

            throw new InspectorException(sprintf('Gemini API request failed: %s', $errMsg));
        }

        $parts = $decoded['candidates'][0]['content']['parts'] ?? [];
        if (!is_array($parts)) {
            throw new InspectorException('Gemini API returned an unexpected response structure.');
        }

        $chunks = [];
        foreach ($parts as $part) {
            if (is_array($part) && empty($part['thought']) && is_string($part['text'] ?? null)) {
                $chunks[] = $part['text'];
            }
        }

        $result = trim(implode('', $chunks));
        if ($result === '') {
            throw new InspectorException('Gemini API returned an empty summary.');
        }

        return $result;
    }
}
