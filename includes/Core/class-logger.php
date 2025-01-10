<?php

namespace WP_Security\Core;

use WP_Security\Core\Logger\LoggerInterface;

/**
 * Core logger class for the WordPress Security Hardening plugin.
 *
 * @package WP_Security
 * @subpackage Core
 * @since 1.0.0
 */
class WP_Security_Logger implements LoggerInterface {
	/**
	 * Instance of this class
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Log file path
	 *
	 * @var string
	 */
	private string $log_file;

	/**
	 * Maximum log file size in bytes
	 *
	 * @var int
	 */
	private int $max_size = 5242880; // 5MB

	/**
	 * Constructor - Initialize logger
	 */
	private function __construct() {
		$upload_dir     = wp_upload_dir();
		$this->log_file = trailingslashit( $upload_dir['basedir'] ) . 'wp-security/security.log';

		// Ensure log directory exists
		wp_mkdir_p( dirname( $this->log_file ) );

		// Schedule cleanup
		if ( ! wp_next_scheduled( 'wp_security_clean_logs' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_clean_logs' );
		}
	}

	/**
	 * Get singleton instance
	 *
	 * @return self
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Logs a message.
	 *
	 * @param string $type The type of log entry.
	 * @param string $message The log message.
	 * @param string $level The severity level (debug, info, warning, error).
	 * @param array  $context Additional context data.
	 * @return bool True on success, false on failure.
	 */
	public function log( string $type, string $message, string $level = 'info', array $context = array() ): bool {
		if ( ! is_writable( dirname( $this->log_file ) ) ) {
			return false;
		}

		// Rotate log if too large
		if ( file_exists( $this->log_file ) && filesize( $this->log_file ) > $this->max_size ) {
			$this->rotate_log();
		}

		$timestamp = current_time( 'mysql' );
		$ip        = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
		$user      = wp_get_current_user();
		$user_id   = $user->ID ?? 0;

		$entry = sprintf(
			"[%s] [%s] [%s] [User:%d] [IP:%s] %s %s\n",
			$timestamp,
			strtoupper( $level ),
			$type,
			$user_id,
			$ip,
			$message,
			! empty( $context ) ? json_encode( $context ) : ''
		);

		$result = file_put_contents( $this->log_file, $entry, FILE_APPEND | LOCK_EX );

		// Notify admin of critical events
		if ( $level === 'error' && apply_filters( 'wp_security_notify_admin', true ) ) {
			$this->notify_admin( $type, $message, $context );
		}

		return $result !== false;
	}

	/**
	 * Gets log entries.
	 *
	 * @param string|null $type Optional. Filter by log type.
	 * @param string|null $level Optional. Filter by severity level.
	 * @param int         $limit Optional. Maximum number of entries to return.
	 * @param int         $offset Optional. Number of entries to skip.
	 * @return array Array of log entries.
	 */
	public function get_logs( ?string $type = null, ?string $level = null, int $limit = 100, int $offset = 0 ): array {
		if ( ! file_exists( $this->log_file ) || ! is_readable( $this->log_file ) ) {
			return array();
		}

		$entries = array_filter(
			array_map( 'trim', file( $this->log_file ) ),
			function ( $line ) use ( $type, $level ) {
				if ( empty( $line ) ) {
					return false;
				}

				if ( $type !== null && ! str_contains( $line, "[$type]" ) ) {
					return false;
				}

				if ( $level !== null && ! str_contains( $line, '[' . strtoupper( $level ) . ']' ) ) {
					return false;
				}

				return true;
			}
		);

		$entries = array_reverse( $entries );
		return array_slice( $entries, $offset, $limit );
	}

	/**
	 * Cleans old log entries.
	 *
	 * @param int $days Optional. Remove entries older than this many days.
	 * @return bool True on success, false on failure.
	 */
	public function clean_logs( int $days = 30 ): bool {
		if ( ! file_exists( $this->log_file ) || ! is_writable( $this->log_file ) ) {
			return false;
		}

		$cutoff      = strtotime( "-$days days" );
		$temp_file   = $this->log_file . '.tmp';
		$handle      = @fopen( $this->log_file, 'r' );
		$temp_handle = @fopen( $temp_file, 'w' );

		if ( ! $handle || ! $temp_handle ) {
			return false;
		}

		while ( ( $line = fgets( $handle ) ) !== false ) {
			if ( preg_match( '/^\[([\d-\s:]+)\]/', $line, $matches ) ) {
				$timestamp = strtotime( $matches[1] );
				if ( $timestamp > $cutoff ) {
					fwrite( $temp_handle, $line );
				}
			}
		}

		fclose( $handle );
		fclose( $temp_handle );

		return rename( $temp_file, $this->log_file );
	}

	/**
	 * Rotates the log file.
	 *
	 * @return bool True on success, false on failure.
	 */
	private function rotate_log(): bool {
		if ( ! file_exists( $this->log_file ) ) {
			return false;
		}

		$backup_file = $this->log_file . '.' . date( 'Y-m-d-H-i-s' );
		return rename( $this->log_file, $backup_file );
	}

	/**
	 * Notifies admin of critical events.
	 *
	 * @param string $type Event type.
	 * @param string $message Event message.
	 * @param array  $context Event context.
	 * @return bool True on success, false on failure.
	 */
	private function notify_admin( string $type, string $message, array $context = array() ): bool {
		$admin_email = get_option( 'admin_email' );
		if ( ! $admin_email ) {
			return false;
		}

		$subject = sprintf( '[%s] Security Alert: %s', get_bloginfo( 'name' ), $type );
		$body    = sprintf(
			"A critical security event has occurred:\n\nType: %s\nMessage: %s\nContext: %s",
			$type,
			$message,
			! empty( $context ) ? json_encode( $context, JSON_PRETTY_PRINT ) : 'None'
		);

		return wp_mail( $admin_email, $subject, $body );
	}
}
