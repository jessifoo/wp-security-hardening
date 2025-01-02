<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Hostinger_Optimizations {
	private $memory_limit;
	private $max_execution_time;
	private $upload_max_filesize;
	private $post_max_size;
	private $max_input_vars;

	public function __construct() {
		$this->init_limits();
	}

	private function init_limits() {
		$this->memory_limit        = $this->parse_size( ini_get( 'memory_limit' ) );
		$this->max_execution_time  = ini_get( 'max_execution_time' );
		$this->upload_max_filesize = $this->parse_size( ini_get( 'upload_max_filesize' ) );
		$this->post_max_size       = $this->parse_size( ini_get( 'post_max_size' ) );
		$this->max_input_vars      = ini_get( 'max_input_vars' );
	}

	private function parse_size( $size ) {
		$unit = preg_replace( '/[^bkmgtpezy]/i', '', $size );
		$size = preg_replace( '/[^0-9\.]/', '', $size );
		if ( $unit ) {
			return round( $size * pow( 1024, stripos( 'bkmgtpezy', strtolower( $unit[0] ) ) ) );
		}
		return round( $size );
	}

	public function get_safe_memory_limit() {
		// Leave 20% memory buffer for WordPress
		return intval( $this->memory_limit * 0.8 );
	}

	public function get_safe_execution_time() {
		// Leave 5 seconds buffer for cleanup
		return max( 20, intval( $this->max_execution_time - 5 ) );
	}

	public function get_max_file_size() {
		// Use the smaller of upload_max_filesize and post_max_size
		return min( $this->upload_max_filesize, $this->post_max_size );
	}

	public function optimize_scan_chunk_size() {
		$memory_available = $this->get_safe_memory_limit();
		// Estimate 2MB per file for scanning
		return max( 5, intval( $memory_available / ( 2 * 1024 * 1024 ) ) );
	}

	public function is_safe_to_scan( $file_path ) {
		if ( ! file_exists( $file_path ) ) {
			return false;
		}

		$file_size = filesize( $file_path );
		$max_size  = $this->get_max_file_size();

		// Skip files larger than 5MB on shared hosting
		if ( $file_size > 5 * 1024 * 1024 ) {
			return false;
		}

		// Check file permissions
		if ( ! is_readable( $file_path ) ) {
			return false;
		}

		return true;
	}

	public function optimize_database_queries() {
		global $wpdb;

		// Use smaller result sets
		$wpdb->query( 'SET SESSION SQL_BIG_SELECTS=0' );
		$wpdb->query( 'SET SESSION group_concat_max_len=1024' );
		$wpdb->query( "SET SESSION sql_mode='STRICT_ALL_TABLES,NO_AUTO_CREATE_USER'" );

		// Optimize temporary tables
		$wpdb->query( 'SET SESSION tmp_table_size=32M' );
		$wpdb->query( 'SET SESSION max_heap_table_size=32M' );
	}

	public function get_optimal_batch_size() {
		// Calculate based on memory and execution time constraints
		$memory_based_size = $this->optimize_scan_chunk_size();
		$time_based_size   = intval( $this->get_safe_execution_time() / 0.1 ); // Assume 0.1s per file
		return min( $memory_based_size, $time_based_size, 100 ); // Never more than 100 files at once
	}

	public function prepare_environment() {
		// Optimize PHP settings for scanning
		@ini_set( 'memory_limit', $this->get_safe_memory_limit() . 'M' );
		@ini_set( 'max_execution_time', $this->get_safe_execution_time() );
		@ini_set( 'display_errors', 0 );
		@ini_set( 'log_errors', 1 );
		@ini_set( 'error_log', WP_CONTENT_DIR . '/security-scanner-errors.log' );

		// Disable potentially interfering functions
		@ini_set( 'opcache.enable', 0 );
		@ini_set( 'zend.enable_gc', 0 );

		// Set appropriate MySQL timeout
		$this->optimize_database_queries();
	}

	public function cleanup_environment() {
		// Restore default PHP settings
		@ini_restore( 'memory_limit' );
		@ini_restore( 'max_execution_time' );
		@ini_restore( 'display_errors' );
		@ini_restore( 'log_errors' );
		@ini_restore( 'error_log' );
		@ini_restore( 'opcache.enable' );
		@ini_restore( 'zend.enable_gc' );

		// Clear any temporary data
		if ( function_exists( 'opcache_reset' ) ) {
			opcache_reset();
		}
		gc_collect_cycles();
	}

	public function get_safe_directories() {
		// Get WordPress directories that are safe to scan
		$upload_dir  = wp_upload_dir();
		$content_dir = WP_CONTENT_DIR;
		$plugin_dir  = WP_PLUGIN_DIR;
		$theme_dir   = get_theme_root();

		$dirs = array(
			'uploads' => $upload_dir['basedir'],
			'plugins' => $plugin_dir,
			'themes'  => $theme_dir,
			'content' => $content_dir,
		);

		// Filter out unreadable directories
		foreach ( $dirs as $key => $dir ) {
			if ( ! is_readable( $dir ) ) {
				unset( $dirs[ $key ] );
			}
		}

		return $dirs;
	}

	public function is_hostinger() {
		// Check if running on Hostinger
		$server_signature = isset( $_SERVER['SERVER_SIGNATURE'] ) ? $_SERVER['SERVER_SIGNATURE'] : '';
		$server_software  = isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : '';

		return (
			stripos( $server_signature, 'hostinger' ) !== false ||
			stripos( $server_software, 'hostinger' ) !== false ||
			file_exists( '/etc/hostinger-system-version' )
		);
	}

	public function get_hostinger_limits() {
		if ( ! $this->is_hostinger() ) {
			return array();
		}

		return array(
			'memory_limit'        => $this->memory_limit,
			'max_execution_time'  => $this->max_execution_time,
			'upload_max_filesize' => $this->upload_max_filesize,
			'post_max_size'       => $this->post_max_size,
			'max_input_vars'      => $this->max_input_vars,
			'safe_memory_limit'   => $this->get_safe_memory_limit(),
			'safe_execution_time' => $this->get_safe_execution_time(),
			'max_file_size'       => $this->get_max_file_size(),
			'optimal_batch_size'  => $this->get_optimal_batch_size(),
		);
	}
}
