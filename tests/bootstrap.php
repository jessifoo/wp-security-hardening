<?php
/**
 * PHPUnit bootstrap file for standalone testing
 */

// Define ABSPATH to prevent direct access check
define( 'ABSPATH', true );

// Load Composer's autoloader
require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// Initialize WP_Mock
WP_Mock::bootstrap();

// Define WordPress constants that might be used in tests
if ( ! defined( 'WP_CONTENT_DIR' ) ) {
	define( 'WP_CONTENT_DIR', dirname( __DIR__ ) . '/wp-content' );
}

if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' );
}

// Define plugin constants
if ( ! defined( 'WP_SECURITY_PLUGIN_DIR' ) ) {
	define( 'WP_SECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'WP_SECURITY_VERSION' ) ) {
	define( 'WP_SECURITY_VERSION', '1.0.0' );
}

// Mock WordPress functions
WP_Mock::userFunction(
	'plugin_dir_path',
	array(
		'return' => function ( $file ) {
			return dirname( $file ) . '/';
		},
	)
);

WP_Mock::userFunction(
	'plugin_dir_url',
	array(
		'return' => function ( $file ) {
			return 'http://example.com/wp-content/plugins/' . basename( dirname( $file ) ) . '/';
		},
	)
);

WP_Mock::userFunction(
	'plugin_basename',
	array(
		'return' => function ( $file ) {
			return basename( dirname( $file ) ) . '/' . basename( $file );
		},
	)
);

WP_Mock::userFunction(
	'wp_remote_get',
	array(
		'return' => array(),
	)
);

WP_Mock::userFunction(
	'is_wp_error',
	array(
		'return' => false,
	)
);

WP_Mock::userFunction(
	'wp_remote_retrieve_body',
	array(
		'return' => '',
	)
);

// Set up a basic autoloader for test classes
spl_autoload_register(
	function ( $class ) {
		$prefix   = 'WP_Security\\Tests\\';
		$base_dir = __DIR__ . '/';

		$len = strlen( $prefix );
		if ( strncmp( $prefix, $class, $len ) !== 0 ) {
			return;
		}

		$relative_class = substr( $class, $len );
		$file           = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

		if ( file_exists( $file ) ) {
			require $file;
		}
	}
);

// Load test utilities
require_once __DIR__ . '/Security/Scanner/Base/MockScanResult.php';

// Load plugin files
require_once dirname( __DIR__ ) . '/wp-security-hardening.php';

// Mock WordPress classes
class WP_Security_Logger {
	public function error( $message, array $context = array() ) {}
	public function warning( $message, array $context = array() ) {}
	public function info( $message, array $context = array() ) {}
	public function debug( $message, array $context = array() ) {}
}

class WP_Security_File_Integrity {
	public function check_core_files() {
		return array(); }
	public function verify_plugin_files() {
		return array(); }
	public function scan_for_malware() {
		return array(); }
	public function quarantine_file( $file ) {
		return true; }
}

class WP_Security_Quarantine_Manager {
	public function quarantine_file( $file, $details ) {
		return true; }
	public function restore_file( $quarantine_name ) {
		return true; }
	public function get_quarantine_list() {
		return array(); }
	public function cleanup_quarantine() {
		return true; }
	public function get_quarantine_stats() {
		return array(); }
}

class WP_Security_Rate_Limiter {
	public function get_daily_calls( $site ) {
		return 0; }
	public function track_api_call( $site ) {
		return true; }
	public function can_make_api_call( $site ) {
		return true; }
}

class WP_Security_Malware_Detector {
	public function full_scan() {
		return true;
	}
}

class WP_Security_DB_Cleaner {
	public function optimize_tables() {
		return true;
	}
}

class WP_Security_Distributed_Scanner {
	public function incremental_scan() {
		return true;
	}
}

class WP_Security_Threat_Intelligence {
	public function analyze_code_content( $code ) {
		return array(
			'is_malicious'  => strpos( $code, 'eval' ) !== false || strpos( $code, 'base64_decode' ) !== false,
			'is_obfuscated' => strpos( $code, 'base64_decode' ) !== false,
		);
	}

	public function extract_patterns_from_code( $code ) {
		return array(
			'dangerous_functions' => array( 'eval', 'system' ),
		);
	}

	public function can_make_api_call( $site ) {
		return true;
	}

	public function track_api_call( $site ) {
		return true;
	}
}

// Mock WordPress globals
global $wpdb;
$wpdb = new class() {
	public $prefix      = 'wp_';
	public $num_queries = 0;

	public function get_results( $query ) {
		return array(); }
	public function prepare( $query, ...$args ) {
		return $query; }
};

// Set up test environment
define( 'WP_SECURITY_PLUGIN_URL', 'http://example.com/wp-content/plugins/wp-security-hardening/' );
