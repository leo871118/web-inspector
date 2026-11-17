<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Exception;

/**
 * Thrown when a target URL or redirect resolves to a loopback, private, or reserved network address.
 */
final class SsrfBlockedException extends InspectorException {}
