<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Http;

use LeandroPerez\WebInspector\Exception\InspectorException;
use LeandroPerez\WebInspector\Exception\SsrfBlockedException;

/**
 * Normalizes target URLs and enforces SSRF network boundary checks.
 */
final class UrlNormalizer
{
    /**
     * Normalizes a raw domain or URL into a canonical HTTP/HTTPS URL.
     *
     * @return array{url: string, host: string, scheme: string}
     */
    public function normalize(string $rawTarget): array
    {
        $trimmed = trim($rawTarget);
        if ($trimmed === '') {
            throw new InspectorException('Target domain or URL cannot be empty.');
        }

        if (!preg_match('#^https?://#i', $trimmed)) {
            $trimmed = 'https://' . $trimmed;
        }

        $parts = parse_url($trimmed);
        if ($parts === false || empty($parts['host'])) {
            throw new InspectorException(sprintf('Invalid target URL format: "%s".', $rawTarget));
        }

        $scheme = strtolower($parts['scheme'] ?? 'https');
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new InspectorException(sprintf('Unsupported URL scheme "%s". Only HTTP and HTTPS are allowed.', $scheme));
        }

        $host = strtolower(trim($parts['host']));
        if (!str_contains($host, '.') && $host !== 'localhost') {
            throw new InspectorException(sprintf('Invalid hostname "%s": a valid TLD is required.', $host));
        }

        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = ($parts['path'] ?? '') !== '' ? $parts['path'] : '/';
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';

        return [
            'url' => $scheme . '://' . $host . $port . $path . $query,
            'host' => $host,
            'scheme' => $scheme,
        ];
    }

    /**
     * Ensures the given hostname or IP does not resolve to loopback, private, or reserved ranges.
     */
    public function assertPublicHost(string $host): void
    {
        $cleanHost = strtolower(trim($host));
        if ($cleanHost === '' || $cleanHost === 'localhost' || str_ends_with($cleanHost, '.local') || str_ends_with($cleanHost, '.lan') || str_ends_with($cleanHost, '.internal')) {
            throw new SsrfBlockedException(sprintf('SSRF protection: local hostname "%s" is blocked.', $host));
        }

        $ips = $this->resolveHostIps($cleanHost);
        foreach ($ips as $ip) {
            if ($ip === '127.0.0.1' || $ip === '::1') {
                throw new SsrfBlockedException(sprintf('SSRF protection: loopback IP "%s" is blocked.', $ip));
            }

            $isPublic = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
            if ($isPublic === false) {
                throw new SsrfBlockedException(sprintf('SSRF protection: private or reserved IP "%s" for host "%s" is blocked.', $ip, $host));
            }
        }
    }

    /**
     * @return list<string>
     */
    private function resolveHostIps(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = [];
        $records = @dns_get_record($host, DNS_A + DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                if (!empty($record['ip']) && is_string($record['ip'])) {
                    $ips[] = $record['ip'];
                } elseif (!empty($record['ipv6']) && is_string($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        if ($ips === []) {
            $fallbackIp = @gethostbyname($host);
            if ($fallbackIp !== $host && filter_var($fallbackIp, FILTER_VALIDATE_IP) !== false) {
                $ips[] = $fallbackIp;
            }
        }

        return array_values(array_unique($ips));
    }
}
