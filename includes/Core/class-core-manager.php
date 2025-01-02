<?php
/**
 * Manages WordPress core file repairs and integrity checks
 */

namespace WP_Security\Core;

use WP_Security\Utils\{Utils, Logger};

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Core_Manager {
	private $backup_dir;
	private $logger;

	public function __construct() {
		$wp_paths         = Utils::get_wp_paths();
		$this->backup_dir = $wp_paths['security'] . '/backups/core';
		$this->logger     = Logger::get_instance();

		// Schedule integrity checks
		if ( ! wp_next_scheduled( 'wp_security_core_check' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_core_check' );
		}
		add_action( 'wp_security_core_check', array( $this, 'check_core_integrity' ) );
	}

	/**
	 * Check and repair WordPress core files
	 */
	public function check_core_integrity() {
		$this->log( 'Starting WordPress core integrity check' );

		try {
			$checksums = Utils::get_core_checksums();
			if ( ! $checksums ) {
				throw new \Exception( 'Could not get WordPress checksums' );
			}

			$modified_files = array();
			$missing_files  = array();

			foreach ( $checksums as $file => $checksum ) {
				$file_path = ABSPATH . $file;

				if ( ! file_exists( $file_path ) ) {
					$missing_files[] = $file;
					continue;
				}

				if ( md5_file( $file_path ) !== $checksum ) {
					$modified_files[] = $file;
				}
			}

			if ( ! empty( $modified_files ) ) {
				$this->log( 'Found modified core files: ' . implode( ', ', $modified_files ), 'warning' );
				foreach ( $modified_files as $file ) {
					$this->repair_core_file( ABSPATH . $file );
				}
			}

			if ( ! empty( $missing_files ) ) {
				$this->log( 'Found missing core files: ' . implode( ', ', $missing_files ), 'warning' );
				foreach ( $missing_files as $file ) {
					$this->restore_core_file( ABSPATH . $file );
				}
			}

			// Check wp-config.php for suspicious content
			$this->check_wp_config();

			// Check .htaccess for suspicious content
			$this->check_htaccess();

		} catch ( \Exception $e ) {
			$this->log( 'Core integrity check failed: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Repair a modified core file
	 */
	private function repair_core_file( $file_path ) {
		try {
			// Create backup
			$backup_path = Utils::backup_file( $file_path, $this->backup_dir );
			$this->log( "Created backup of $file_path at $backup_path" );

			// Download fresh copy
			$relative_path = str_replace( ABSPATH, '', $file_path );
			$url           = 'https://core.svn.wordpress.org/tags/' . get_bloginfo( 'version' ) . '/' . $relative_path;

			$response = wp_remote_get( $url );
			if ( is_wp_error( $response ) ) {
				throw new \Exception( 'Failed to download core file: ' . $response->get_error_message() );
			}

			if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
				throw new \Exception( 'Failed to download core file: HTTP ' . wp_remote_retrieve_response_code( $response ) );
			}

			Utils::write_file( $file_path, wp_remote_retrieve_body( $response ) );
			$this->log( "Repaired core file: $file_path" );

		} catch ( \Exception $e ) {
			$this->log( 'Failed to repair core file: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Restore a missing core file
	 */
	private function restore_core_file( $file_path ) {
		try {
			wp_mkdir_p( dirname( $file_path ) );

			$relative_path = str_replace( ABSPATH, '', $file_path );
			$url           = 'https://core.svn.wordpress.org/tags/' . get_bloginfo( 'version' ) . '/' . $relative_path;

			$response = wp_remote_get( $url );
			if ( is_wp_error( $response ) ) {
				throw new \Exception( 'Failed to download core file: ' . $response->get_error_message() );
			}

			if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
				throw new \Exception( 'Failed to download core file: HTTP ' . wp_remote_retrieve_response_code( $response ) );
			}

			Utils::write_file( $file_path, wp_remote_retrieve_body( $response ) );
			$this->log( "Restored missing core file: $file_path" );

		} catch ( \Exception $e ) {
			$this->log( 'Failed to restore core file: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Check wp-config.php for suspicious content
	 */
	private function check_wp_config() {
		$config_path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $config_path ) ) {
			$this->log( 'wp-config.php not found', 'error' );
			return;
		}

		try {
			$content = Utils::read_file( $config_path );

			$suspicious_patterns = array(
				'/eval\s*\(/'          => 'Found eval() function',
				'/base64_decode\s*\(/' => 'Found base64_decode() function',
				'/system\s*\(/'        => 'Found system() function',
				'/exec\s*\(/'          => 'Found exec() function',
				'/shell_exec\s*\(/'    => 'Found shell_exec() function',
				'/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\)/' => 'Found dynamic function call',
			);

			foreach ( $suspicious_patterns as $pattern => $message ) {
				if ( preg_match( $pattern, $content ) ) {
					$this->log( "Suspicious content in wp-config.php: $message", 'critical' );
				}
			}
		} catch ( \Exception $e ) {
			$this->log( 'Failed to check wp-config.php: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Check .htaccess for suspicious content
	 */
	private function check_htaccess() {
		$htaccess_path = ABSPATH . '.htaccess';
		if ( ! file_exists( $htaccess_path ) ) {
			return; // .htaccess is optional
		}

		try {
			$content = Utils::read_file( $htaccess_path );

			$suspicious_patterns = array(
				'/RewriteRule.*base64_decode/i'            => 'Found base64_decode in RewriteRule',
				'/RewriteRule.*eval/i'                     => 'Found eval in RewriteRule',
				'/SetHandler\s+application\/x-httpd-php/i' => 'Found PHP handler modification',
				'/AddType\s+application\/x-httpd-php/i'    => 'Found PHP type modification',
				'/php_value.*auto_prepend_file/i'          => 'Found auto_prepend_file directive',
				'/php_value.*auto_append_file/i'           => 'Found auto_append_file directive',
			);

			foreach ( $suspicious_patterns as $pattern => $message ) {
				if ( preg_match( $pattern, $content ) ) {
					$this->log( "Suspicious content in .htaccess: $message", 'critical' );
				}
			}
		} catch ( \Exception $e ) {
			$this->log( 'Failed to check .htaccess: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Log a message
	 */
	private function log( $message, $level = 'info' ) {
		$this->logger->log( $message, $level, 'core' );
	}
}
