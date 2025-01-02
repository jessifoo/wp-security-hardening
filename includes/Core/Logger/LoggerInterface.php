<?php

namespace WP_Security\Core\Logger;

/**
 * Interface for logging functionality.
 *
 * @package WP_Security
 * @subpackage Core\Logger
 * @since 1.0.0
 */
interface LoggerInterface {
    /**
     * Logs a message.
     *
     * @param string $type The type of log entry.
     * @param string $message The log message.
     * @param string $level The severity level (debug, info, warning, error).
     * @param array  $context Additional context data.
     * @return bool True on success, false on failure.
     */
    public function log(string $type, string $message, string $level = 'info', array $context = []): bool;

    /**
     * Gets log entries.
     *
     * @param string|null $type Optional. Filter by log type.
     * @param string|null $level Optional. Filter by severity level.
     * @param int        $limit Optional. Maximum number of entries to return.
     * @param int        $offset Optional. Number of entries to skip.
     * @return array Array of log entries.
     */
    public function get_logs(?string $type = null, ?string $level = null, int $limit = 100, int $offset = 0): array;

    /**
     * Cleans old log entries.
     *
     * @param int $days Optional. Remove entries older than this many days.
     * @return bool True on success, false on failure.
     */
    public function clean_logs(int $days = 30): bool;
}
