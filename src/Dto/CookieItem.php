<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Dto;

use JsonSerializable;

/**
 * Audited metadata and security flags for a single HTTP Set-Cookie header.
 */
final readonly class CookieItem implements JsonSerializable
{
    public function __construct(
        public string $name,
        public string $maskedValue,
        public bool $secure,
        public bool $httpOnly,
        public ?string $sameSite,
        public ?string $expires,
        public ?int $maxAge,
        public ?string $domain,
        public string $path,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'name' => $this->name,
            'masked_value' => $this->maskedValue,
            'secure' => $this->secure,
            'httponly' => $this->httpOnly,
            'samesite' => $this->sameSite,
            'expires' => $this->expires,
            'max_age' => $this->maxAge,
            'domain' => $this->domain,
            'path' => $this->path,
        ];
    }
}
