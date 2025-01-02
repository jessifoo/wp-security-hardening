<?php

namespace WP_Security\Monitoring\Resource\Exception;

/**
 * Exception thrown when resource limits are exceeded
 */
class ResourceLimitException extends \Exception {
	public const TIME_LIMIT_EXCEEDED   = 1;
	public const MEMORY_LIMIT_EXCEEDED = 2;
	public const FILE_LIMIT_EXCEEDED   = 3;
	public const DB_LIMIT_EXCEEDED     = 4;
}
