<?php

namespace WP_Security\Core\Logger;

/**
 * PSR-3 compliant WordPress security logger
 *
 * @package WP_Security
 * @subpackage Core\Logger
 * @since 1.0.0
 */
class WP_Security_Logger implements LoggerInterface {

	/**
	 * Option name for storing log settings
	 *
	 * @var string
	 */
	private const LOG_SETTINGS_OPTION = 'wp_security_log_settings';

	/**
	 * Log file path
	 *
	 * @var string
	 */
	private $_log_file;

	/**
	 * Log levels from PSR-3
	 *
	 * @var array
	 */
	private const LEVELS = array(
		'emergency' => 0,
		'alert'     => 1,
		'critical'  => 2,
		'error'     => 3,
		'warning'   => 4,
		'notice'    => 5,
		'info'      => 6,
		'debug'     => 7,
	);

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_log_file = WP_CONTENT_DIR . '/security/security.log';
		wp_mkdir_p( dirname( $this->_log_file ) );
	}

	/**
	 * System is unusable.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function emergency( $message, array $context = array() ) {
		$this->log( 'emergency', $message, $context );
	}

	/**
	 * Action must be taken immediately.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function alert( $message, array $context = array() ) {
		$this->log( 'alert', $message, $context );
	}

	/**
	 * Critical conditions.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function critical( $message, array $context = array() ) {
		$this->log( 'critical', $message, $context );
	}

	/**
	 * Runtime errors that do not require immediate action.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function error( $message, array $context = array() ) {
		$this->log( 'error', $message, $context );
	}

	/**
	 * Exceptional occurrences that are not errors.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function warning( $message, array $context = array() ) {
		$this->log( 'warning', $message, $context );
	}

	/**
	 * Normal but significant events.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function notice( $message, array $context = array() ) {
		$this->log( 'notice', $message, $context );
	}

	/**
	 * Interesting events.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function info( $message, array $context = array() ) {
		$this->log( 'info', $message, $context );
	}

	/**
	 * Detailed debug information.
	 *
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 */
	public function debug( $message, array $context = array() ) {
		$this->log( 'debug', $message, $context );
	}

	/**
	 * Logs with an arbitrary level.
	 *
	 * @param string $level   Log level.
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 *
	 * @throws \InvalidArgumentException When invalid log level provided.
	 */
	public function log( $level, $message, array $context = array() ) {
		if ( ! isset( self::LEVELS[ $level ] ) ) {
			throw new \InvalidArgumentException( "Invalid log level: $level" );
		}

		$settings = get_option(
			self::LOG_SETTINGS_OPTION,
			array(
				'min_level' => 'info',
				'max_size'  => 10 * 1024 * 1024, // 10MB
			)
		);

		// Check if we should log this level.
		if ( self::LEVELS[ $level ] > self::LEVELS[ $settings['min_level'] ] ) {
			return;
		}

		// Rotate log if needed.
		$this->maybe_rotate_log( $settings['max_size'] );

		// Format the log entry.
		$entry = $this->format_log_entry( $level, $message, $context );

		// Write to log file.
		error_log( $entry . PHP_EOL, 3, $this->_log_file );

		/**
		 * Fires after a security log entry is written
		 *
		 * @param string $level   Log level
		 * @param string $message Log message
		 * @param array  $context Additional context
		 */
		do_action( 'wp_security_log', $level, $message, $context );
	}

	/**
	 * Format a log entry
	 *
	 * @param string $level   Log level.
	 * @param string $message Log message.
	 * @param array  $context Additional context data.
	 * @return string Formatted log entry.
	 */
	private function format_log_entry( $level, $message, array $context ) {
		$timestamp = current_time( 'c' );
		$pid       = getmypid();

		// Replace context placeholders.
		$message = $this->interpolate( $message, $context );

		// Add context as JSON if not empty.
		$context_json = ! empty( $context ) ? ' ' . wp_json_encode( $context ) : '';

		return sprintf(
			'[%s] %s.%s: %s%s',
			$timestamp,
			strtoupper( $level ),
			$pid,
			$message,
			$context_json
		);
	}

	/**
	 * Replace placeholders in message with context values
	 *
	 * @param string $message Log message with placeholders.
	 * @param array  $context Values to replace placeholders.
	 * @return string Message with replaced placeholders.
	 */
	private function interpolate( $message, array $context ) {
		$replace = array();
		foreach ( $context as $key => $val ) {
			if ( is_string( $val ) || method_exists( $val, '__toString' ) ) {
				$replace[ '{' . $key . '}' ] = $val;
			}
		}
		return strtr( $message, $replace );
	}

	/**
	 * Rotate log file if it exceeds max size
	 *
	 * @param int $max_size Maximum log file size in bytes.
	 */
	private function maybe_rotate_log( $max_size ) {
		if ( ! file_exists( $this->_log_file ) ) {
			return;
		}

		if ( filesize( $this->_log_file ) < $max_size ) {
			return;
		}

		$backup_file = $this->_log_file . '.' . date( 'Y-m-d-H-i-s' );
		rename( $this->_log_file, $backup_file );

		// Compress old log.
		if ( function_exists( 'gzopen' ) ) {
			$gz = gzopen( $backup_file . '.gz', 'w9' );
			gzwrite( $gz, file_get_contents( $backup_file ) );
			gzclose( $gz );
			unlink( $backup_file );
		}

		// Clean old logs.
		$this->clean_old_logs();
	}

	/**
	 * Remove old rotated log files
	 */
	private function clean_old_logs() {
		$logs = glob( $this->_log_file . '.*.gz' );
		if ( count( $logs ) <= 5 ) {
			return;
		}

		// Keep only last 5 logs.
		$logs = array_slice( $logs, 0, -5 );
		foreach ( $logs as $log ) {
			unlink( $log );
		}
	}
}
