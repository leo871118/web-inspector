<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Immutable representation of an HTTP response captured during inspection.
 */
final readonly class HttpResponse implements JsonSerializable
{
    /**
     * @param array<string, list<string>> $headers Lowercase header names mapped to value lists
     * @param list<string> $rawCookies Raw Set-Cookie header values
     */
    public function __construct(
        public int $statusCode,
        public int $initialStatusCode,
        public string $effectiveUrl,
        public string $body,
        public array $headers,
        public array $rawCookies,
        public int $redirectCount,
        public int $durationMs,
        public ?string $protocolVersion = null,
    ) {}

    public function getHeader(string $name): ?string
    {
        $key = strtolower($name);

        return $this->headers[$key][0] ?? null;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[strtolower($name)]) && $this->headers[strtolower($name)] !== [];
    }

    public function isSuccess(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'status_code' => $this->statusCode,
            'initial_status_code' => $this->initialStatusCode,
            'effective_url' => $this->effectiveUrl,
            'redirect_count' => $this->redirectCount,
            'duration_ms' => $this->durationMs,
            'protocol_version' => $this->protocolVersion,
        ];
    }
}
