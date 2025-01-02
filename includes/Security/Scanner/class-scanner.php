<?php
/**
 * Main scanner class that handles all file scanning, malware detection, and code analysis
 */

namespace WP_Security\Scanner;

use WP_Security\Utils\{Utils, Logger};

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scanner exception class
 */
class Scanner_Exception extends \Exception {}

class Scanner {
	// Severity levels
	const SEVERITY_LOW      = 'low';
	const SEVERITY_MEDIUM   = 'medium';
	const SEVERITY_HIGH     = 'high';
	const SEVERITY_CRITICAL = 'critical';

	// Scan types
	const TYPE_CORE   = 'core';
	const TYPE_PLUGIN = 'plugin';
	const TYPE_THEME  = 'theme';
	const TYPE_UPLOAD = 'upload';

	// Pattern types
	const PATTERN_REGEX = 'regex';
	const PATTERN_HASH  = 'hash';
	const PATTERN_TOKEN = 'token';

	private $patterns       = array();
	private $token_patterns = array();
	private $last_scan      = 0;
	private $log_file;
	private $modified_files = array();
	private $quarantine_dir;
	private $scan_results = array();

	/**
	 * Initialize scanner
	 */
	public function __construct() {
		$wp_paths             = Utils::get_wp_paths();
		$this->quarantine_dir = $wp_paths['security'] . '/quarantine';
		$this->log_file       = $wp_paths['security'] . '/scanner.log';

		// Ensure directories exist
		wp_mkdir_p( $this->quarantine_dir );
		wp_mkdir_p( dirname( $this->log_file ) );

		// Load malware patterns
		$this->load_patterns();

		// Initialize token patterns
		$this->init_token_patterns();

		// Schedule scans
		if ( ! wp_next_scheduled( 'wp_security_scan' ) ) {
			wp_schedule_event( time(), 'hourly', 'wp_security_scan' );
		}
		add_action( 'wp_security_scan', array( $this, 'run_scan' ) );
	}

	/**
	 * Get scan results
	 */
	public function get_results() {
		return $this->scan_results;
	}

	/**
	 * Add scan result
	 */
	private function add_result( $file, $type, $severity, $message, $context = array() ) {
		$this->scan_results[] = array(
			'file'      => $file,
			'type'      => $type,
			'severity'  => $severity,
			'message'   => $message,
			'context'   => $context,
			'timestamp' => time(),
		);
	}

	/**
	 * Handle errors during scan
	 */
	private function handle_error( $error, $context = array() ) {
		$message = $error instanceof \Exception ? $error->getMessage() : $error;
		$this->log( $message, 'error' );

		if ( $context ) {
			$this->log( 'Error context: ' . json_encode( $context ), 'debug' );
		}

		// Add to scan results
		$this->add_result(
			$context['file'] ?? 'unknown',
			$context['type'] ?? 'error',
			self::SEVERITY_HIGH,
			$message,
			$context
		);

		// Throw exception only for critical errors
		if ( isset( $context['critical'] ) && $context['critical'] ) {
			throw new Scanner_Exception( $message );
		}
	}

	/**
	 * Load malware patterns
	 */
	private function load_patterns() {
		$this->patterns = array(
			// PHP Shells
			'php_shell'        => array(
				'pattern'  => '/(?:passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile|php_uname|eval)\s*\(.*\)/',
				'severity' => 'critical',
			),
			// Obfuscated code
			'obfuscation'      => array(
				'pattern'  => '/(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*=[\'"]\w+[\'"]\s*;[\s\n\r]*){4,}/',
				'severity' => 'warning',
			),
			// Base64 encoded PHP code
			'base64_php'       => array(
				'pattern'  => '/[\'"]([A-Za-z0-9+\/]{30,})[\'"]/',
				'severity' => 'critical',
			),
			// Common malware functions
			'malware_func'     => array(
				'pattern'  => '/(?:assert|create_function|gzinflate|str_rot13|strrev|substr|chr|ord)\s*\(/',
				'severity' => 'warning',
			),
			// Suspicious WordPress modifications
			'wp_modifications' => array(
				'pattern'  => '/add_action\s*\(\s*[\'"]wp_head[\'"]\s*,.*(?:eval|base64_decode|gzinflate)/',
				'severity' => 'critical',
			),
		);
	}

	/**
	 * Initialize PHP token patterns for deeper code analysis
	 */
	private function init_token_patterns() {
		$this->token_patterns = array(
			'eval_usage'           => array(
				'tokens'      => array( T_EVAL ),
				'severity'    => 'critical',
				'description' => 'Use of eval() function detected',
			),
			'dynamic_function'     => array(
				'tokens'      => array( T_VARIABLE, T_STRING ),
				'context'     => array( 'create_function', 'call_user_func', 'call_user_func_array' ),
				'severity'    => 'warning',
				'description' => 'Dynamic function execution detected',
			),
			'file_operations'      => array(
				'tokens'      => array( T_STRING ),
				'context'     => array( 'fopen', 'file_get_contents', 'file_put_contents', 'unlink', 'chmod' ),
				'severity'    => 'warning',
				'description' => 'Suspicious file operation detected',
			),
			'request_manipulation' => array(
				'tokens'      => array( T_VARIABLE ),
				'context'     => array( '$_GET', '$_POST', '$_REQUEST', '$_SERVER' ),
				'severity'    => 'warning',
				'description' => 'Direct request variable usage',
			),
			'object_injection'     => array(
				'tokens'      => array( T_STRING ),
				'context'     => array( 'unserialize' ),
				'severity'    => 'critical',
				'description' => 'Possible PHP object injection',
			),
		);
	}

	/**
	 * Run full scan
	 */
	public function run_scan() {
		global $wpdb;

		// Check if we should run based on last scan time
		$now = time();
		if ( ( $now - $this->last_scan ) < HOUR_IN_SECONDS ) {
			return;
		}

		$this->log( 'Starting full scan' );

		try {
			// Scan WordPress core files
			$this->scan_wordpress_core();

			// Scan plugins
			$this->scan_plugins();

			// Scan themes
			$this->scan_themes();

			// Scan uploads
			$this->scan_uploads();

			// Clean database
			$this->clean_database();

			$this->last_scan = $now;
			update_option( 'wp_security_last_scan', $now );

			$this->log( 'Scan completed successfully' );

		} catch ( \Exception $e ) {
			$this->log( 'Scan failed: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Scan WordPress core files
	 */
	private function scan_wordpress_core() {
		$this->log( 'Scanning WordPress core files' );

		// Get core file checksums
		try {
			$checksums = Utils::get_core_checksums();
			if ( ! $checksums ) {
				throw new Scanner_Exception( 'Could not get WordPress checksums' );
			}

			foreach ( $checksums as $file => $checksum ) {
				$file_path = ABSPATH . $file;
				if ( ! file_exists( $file_path ) ) {
					$this->log( "Missing core file: $file", 'warning' );
					continue;
				}

				if ( md5_file( $file_path ) !== $checksum ) {
					$this->handle_modified_file( $file_path, self::TYPE_CORE );
				}
			}
		} catch ( \Exception $e ) {
			$this->handle_error(
				$e,
				array(
					'file' => 'core_files',
					'type' => self::TYPE_CORE,
				)
			);
		}
	}

	/**
	 * Scan plugin files
	 */
	private function scan_plugins() {
		$this->log( 'Scanning plugin files' );

		$plugins_dir = WP_PLUGIN_DIR;
		if ( ! is_dir( $plugins_dir ) ) {
			return;
		}

		$plugins = scandir( $plugins_dir );
		foreach ( $plugins as $plugin ) {
			if ( $plugin === '.' || $plugin === '..' ) {
				continue;
			}

			$plugin_path = $plugins_dir . '/' . $plugin;
			if ( is_dir( $plugin_path ) ) {
				$this->scan_directory( $plugin_path, 'plugin' );
			}
		}
	}

	/**
	 * Scan theme files
	 */
	private function scan_themes() {
		$this->log( 'Scanning theme files' );

		$themes_dir = get_theme_root();
		if ( ! is_dir( $themes_dir ) ) {
			return;
		}

		$themes = scandir( $themes_dir );
		foreach ( $themes as $theme ) {
			if ( $theme === '.' || $theme === '..' ) {
				continue;
			}

			$theme_path = $themes_dir . '/' . $theme;
			if ( is_dir( $theme_path ) ) {
				$this->scan_directory( $theme_path, 'theme' );
			}
		}
	}

	/**
	 * Scan uploads directory
	 */
	private function scan_uploads() {
		$this->log( 'Scanning uploads directory' );

		$uploads_dir = wp_upload_dir()['basedir'];
		if ( ! is_dir( $uploads_dir ) ) {
			return;
		}

		$this->scan_directory( $uploads_dir, 'upload' );
	}

	/**
	 * Scan a directory recursively
	 */
	private function scan_directory( $dir, $type ) {
		if ( ! is_readable( $dir ) ) {
			$this->log( "Directory not readable: $dir", 'error' );
			return;
		}

		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \RecursiveDirectoryIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && $this->should_scan_file( $file ) ) {
				$this->scan_file( $file->getPathname(), $type );
			}
		}
	}

	/**
	 * Check if file should be scanned
	 */
	private function should_scan_file( $file ) {
		// Skip non-PHP files in uploads
		if ( strpos( $file, wp_upload_dir()['basedir'] ) === 0 ) {
			return pathinfo( $file, PATHINFO_EXTENSION ) === 'php';
		}

		// Skip certain files/directories
		$skip_patterns = array(
			'/\.git/',
			'/\.svn/',
			'/vendor/',
			'/node_modules/',
			'/\.log$/',
			'/\.txt$/',
			'/\.md$/',
		);

		foreach ( $skip_patterns as $pattern ) {
			if ( preg_match( $pattern, $file ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Analyze PHP code for security issues
	 */
	private function analyze_php_code( $content, $file_path ) {
		$tokens          = Utils::get_php_tokens( $content );
		$issues          = array();
		$in_function     = false;
		$function_tokens = array();
		$line            = 1;

		foreach ( $tokens as $token ) {
			if ( is_array( $token ) ) {
				list($token_id, $text, $line) = $token;

				// Track function context
				if ( $token_id === T_FUNCTION ) {
					$in_function     = true;
					$function_tokens = array();
				}

				// Check token patterns
				foreach ( $this->token_patterns as $pattern_name => $pattern ) {
					if ( in_array( $token_id, $pattern['tokens'] ) ) {
						if ( isset( $pattern['context'] ) ) {
							if ( is_string( $text ) && in_array( $text, $pattern['context'] ) ) {
								$issues[] = array(
									'type'        => $pattern_name,
									'line'        => $line,
									'severity'    => $pattern['severity'],
									'description' => $pattern['description'],
								);
							}
						} else {
							$issues[] = array(
								'type'        => $pattern_name,
								'line'        => $line,
								'severity'    => $pattern['severity'],
								'description' => $pattern['description'],
							);
						}
					}
				}

				// Store tokens if in function
				if ( $in_function ) {
					$function_tokens[] = $token;
				}
			} elseif ( $token === '{' && $in_function ) {
					$function_tokens[] = $token;
			} elseif ( $token === '}' && $in_function ) {
				$in_function = false;
				$this->analyze_function( $function_tokens, $file_path, $line );
			}
		}

		return $issues;
	}

	/**
	 * Analyze function for security issues
	 */
	private function analyze_function( $tokens, $file_path, $line ) {
		$dangerous_combinations = array(
			// eval with variable input
			array( 'eval', 'variable' ),
			// unserialize with user input
			array( 'unserialize', 'request' ),
			// file operations with variable paths
			array( 'file_operation', 'variable' ),
		);

		$found_tokens = array();
		foreach ( $tokens as $token ) {
			if ( is_array( $token ) ) {
				list($token_id, $text) = $token;

				if ( $token_id === T_STRING && in_array( $text, array( 'eval', 'unserialize' ) ) ) {
					$found_tokens[] = $text;
				} elseif ( $token_id === T_VARIABLE ) {
					$found_tokens[] = 'variable';
					if ( in_array( $text, array( '$_GET', '$_POST', '$_REQUEST' ) ) ) {
						$found_tokens[] = 'request';
					}
				}
			}
		}

		foreach ( $dangerous_combinations as $combination ) {
			if ( count( array_intersect( $combination, $found_tokens ) ) === count( $combination ) ) {
				$this->log(
					sprintf(
						'Dangerous code pattern found in %s line %d: %s',
						$file_path,
						$line,
						implode( ' with ', $combination )
					),
					'critical'
				);
			}
		}
	}

	/**
	 * Scan individual file
	 */
	private function scan_file( $file_path, $type ) {
		try {
			if ( ! Utils::is_php_file( $file_path ) ) {
				return;
			}

			$content = Utils::read_file( $file_path );

			// Perform pattern-based scan
			foreach ( $this->patterns as $name => $pattern ) {
				if ( preg_match( $pattern['pattern'], $content ) ) {
					$this->handle_infected_file( $file_path, $type, $name, $pattern['severity'] );
					return;
				}
			}

			// Perform deeper code analysis
			$tokens = Utils::get_php_tokens( $content );
			if ( ! empty( $tokens ) ) {
				$issues = $this->analyze_php_code( $tokens, $file_path );
				if ( ! empty( $issues ) ) {
					foreach ( $issues as $issue ) {
						$this->log(
							sprintf(
								'%s in %s line %d: %s',
								$issue['severity'],
								$file_path,
								$issue['line'],
								$issue['description']
							),
							$issue['severity']
						);
						if ( $issue['severity'] === self::SEVERITY_CRITICAL ) {
							$this->handle_infected_file( $file_path, $type, $issue['type'], $issue['severity'] );
							return;
						}
					}
				}
			}
		} catch ( \Exception $e ) {
			$this->handle_error(
				$e,
				array(
					'file' => $file_path,
					'type' => $type,
				)
			);
		}
	}

	/**
	 * Handle infected file
	 */
	private function handle_infected_file( $file_path, $type, $pattern_name, $severity ) {
		$this->log( "Found infection in $file_path: $pattern_name ($severity)", 'warning' );

		// Backup file before modification
		$backup_path = Utils::backup_file( $file_path, $this->quarantine_dir );
		$this->log( "Created backup at: $backup_path" );

		if ( $type === 'core' ) {
			// For core files, try to restore from WordPress
			$this->restore_core_file( $file_path );
		} else {
			// For other files, try to clean or quarantine
			$this->clean_or_quarantine( $file_path, $type );
		}
	}

	/**
	 * Restore core file from WordPress
	 */
	private function restore_core_file( $file_path ) {
		$relative_path = str_replace( ABSPATH, '', $file_path );
		$checksums     = Utils::get_core_checksums();

		if ( isset( $checksums[ $relative_path ] ) ) {
			$url      = 'https://core.svn.wordpress.org/tags/' . get_bloginfo( 'version' ) . '/' . $relative_path;
			$response = wp_remote_get( $url );

			if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
				Utils::write_file( $file_path, wp_remote_retrieve_body( $response ) );
				$this->log( "Restored core file: $file_path" );
			}
		}
	}

	/**
	 * Clean file or move to quarantine
	 */
	private function clean_or_quarantine( $file_path, $type ) {
		try {
			// Backup file before modification
			$backup_path = Utils::backup_file( $file_path, $this->quarantine_dir );
			$this->log( "Created backup at: $backup_path" );

			$content = Utils::read_file( $file_path );
			$cleaned = false;

			// Remove dangerous patterns
			$cleaners = array(
				// Remove eval with base64
				'/eval\s*\(\s*base64_decode\s*\([^\)]+\)\s*\)\s*;?/' => '',
				// Remove eval with gzinflate
				'/eval\s*\(\s*gzinflate\s*\([^\)]+\)\s*\)\s*;?/' => '',
				// Remove suspicious object instantiation
				'/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*new\s+\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*;/' => '',
				// Remove long obfuscated strings
				'/[\'"]((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=){1})[\'"]/' => '""',
				// Remove dynamic function calls
				'/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\)/' => '',
			);

			foreach ( $cleaners as $pattern => $replacement ) {
				$new_content = preg_replace( $pattern, $replacement, $content );
				if ( $new_content !== $content ) {
					$content = $new_content;
					$cleaned = true;
				}
			}

			if ( $cleaned ) {
				Utils::write_file( $file_path, $content );
				$this->log( "Cleaned file: $file_path" );
			} else {
				// Move to quarantine if couldn't clean
				$quarantine_path = $this->quarantine_dir . '/' . basename( $file_path ) . '.' . time() . '.quarantine';
				rename( $file_path, $quarantine_path );
				$this->log( "Quarantined file: $file_path" );
			}
		} catch ( \Exception $e ) {
			$this->handle_error(
				$e,
				array(
					'file' => $file_path,
					'type' => $type,
				)
			);
		}
	}

	/**
	 * Clean database
	 */
	private function clean_database() {
		global $wpdb;

		$this->log( 'Cleaning database' );

		// Clean post content
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->posts} SET post_content = REPLACE(post_content, %s, '') 
                WHERE post_content LIKE %s",
				'eval(base64_decode(',
				'%eval(base64_decode(%'
			)
		);

		// Clean option values
		$suspicious_options = $wpdb->get_results(
			"SELECT option_name, option_value FROM {$wpdb->options} 
            WHERE option_value LIKE '%eval%' 
            OR option_value LIKE '%base64_decode%'
            OR option_value LIKE '%gzinflate%'"
		);

		foreach ( $suspicious_options as $option ) {
			delete_option( $option->option_name );
			$this->log( "Removed suspicious option: {$option->option_name}" );
		}
	}

	/**
	 * Get WordPress core checksums
	 */
	private function get_core_checksums() {
		return Utils::get_core_checksums();
	}

	/**
	 * Log message
	 */
	private function log( $message, $level = 'info' ) {
		Logger::get_instance()->log( $message, $level, 'scanner' );
	}
}
