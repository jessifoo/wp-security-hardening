<?php
/**
 * Centralized logging functionality for the security plugin
 */

namespace WP_Security\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Logger {
	private static $instance = null;
	private $log_dir;
	private $default_log;
	private $log_files   = array();
	private $buffer      = array();
	private $buffer_size = 10; // Number of entries to buffer before writing

	private function __construct() {
		$this->log_dir     = WP_CONTENT_DIR . '/security/logs';
		$this->default_log = $this->log_dir . '/security.log';

		// Ensure log directory exists
		wp_mkdir_p( $this->log_dir );

		// Register shutdown function to flush buffers
		register_shutdown_function( array( $this, 'flush_buffers' ) );

		// Setup log rotation
		if ( ! wp_next_scheduled( 'wp_security_rotate_logs' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_rotate_logs' );
		}
		add_action( 'wp_security_rotate_logs', array( $this, 'rotate_logs' ) );
	}

	public static function get_instance() {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Log a message
	 *
	 * @param string $message Message to log
	 * @param string $level Log level (debug, info, warning, error, critical)
	 * @param string $component Component name (scanner, core, network, etc.)
	 * @param array  $context Additional context
	 */
	public function log( $message, $level = 'info', $component = 'general', $context = array() ) {
		$time      = date( 'Y-m-d H:i:s' );
		$log_entry = sprintf(
			"[%s] [%s] [%s] %s%s\n",
			$time,
			strtoupper( $level ),
			$component,
			$message,
			! empty( $context ) ? ' ' . json_encode( $context ) : ''
		);

		// Add to buffer
		$log_file = $this->get_log_file( $component );
		if ( ! isset( $this->buffer[ $log_file ] ) ) {
			$this->buffer[ $log_file ] = array();
		}
		$this->buffer[ $log_file ][] = $log_entry;

		// Write if buffer is full
		if ( count( $this->buffer[ $log_file ] ) >= $this->buffer_size ) {
			$this->write_log( $log_file );
		}

		// Also write immediately for critical errors
		if ( $level === 'critical' ) {
			$this->write_log( $log_file );
		}
	}

	/**
	 * Get appropriate log file for component
	 */
	private function get_log_file( $component ) {
		if ( ! isset( $this->log_files[ $component ] ) ) {
			$this->log_files[ $component ] = $this->log_dir . '/' . $component . '.log';
		}
		return $this->log_files[ $component ];
	}

	/**
	 * Write buffered entries to log file
	 */
	private function write_log( $log_file ) {
		if ( ! isset( $this->buffer[ $log_file ] ) || empty( $this->buffer[ $log_file ] ) ) {
			return;
		}

		$entries = implode( '', $this->buffer[ $log_file ] );
		file_put_contents( $log_file, $entries, FILE_APPEND );
		$this->buffer[ $log_file ] = array();
	}

	/**
	 * Flush all log buffers
	 */
	public function flush_buffers() {
		foreach ( $this->buffer as $log_file => $entries ) {
			$this->write_log( $log_file );
		}
	}

	/**
	 * Rotate log files
	 */
	public function rotate_logs() {
		$max_size  = 10 * 1024 * 1024; // 10MB
		$max_files = 5; // Keep 5 rotated files

		foreach ( $this->log_files as $component => $log_file ) {
			if ( ! file_exists( $log_file ) ) {
				continue;
			}

			if ( filesize( $log_file ) > $max_size ) {
				for ( $i = $max_files - 1; $i > 0; $i-- ) {
					$old_file = $log_file . '.' . $i;
					$new_file = $log_file . '.' . ( $i + 1 );
					if ( file_exists( $old_file ) ) {
						rename( $old_file, $new_file );
					}
				}

				rename( $log_file, $log_file . '.1' );
				touch( $log_file );
			}
		}
	}

	/**
	 * Get logs for a component
	 *
	 * @param string $component Component name
	 * @param int    $lines Number of lines to retrieve
	 * @return array Log entries
	 */
	public function get_logs( $component = 'general', $lines = 100 ) {
		$log_file = $this->get_log_file( $component );
		if ( ! file_exists( $log_file ) ) {
			return array();
		}

		// Flush buffer first to ensure we have all entries
		$this->write_log( $log_file );

		$entries = array();
		$handle  = fopen( $log_file, 'r' );
		if ( $handle ) {
			$position   = filesize( $log_file );
			$chunk_size = 4096;
			$line_count = 0;

			while ( $position > 0 && $line_count < $lines ) {
				$read_size = min( $chunk_size, $position );
				$position -= $read_size;
				fseek( $handle, $position );
				$chunk       = fread( $handle, $read_size );
				$chunk_lines = explode( "\n", $chunk );

				foreach ( array_reverse( $chunk_lines ) as $line ) {
					if ( ! empty( $line ) ) {
						$entries[] = $line;
						++$line_count;
						if ( $line_count >= $lines ) {
							break;
						}
					}
				}
			}
			fclose( $handle );
		}

		return array_reverse( $entries );
	}

	/**
	 * Clear logs for a component
	 */
	public function clear_logs( $component = 'general' ) {
		$log_file = $this->get_log_file( $component );
		if ( file_exists( $log_file ) ) {
			unlink( $log_file );
		}
		$this->buffer[ $log_file ] = array();
	}
}
