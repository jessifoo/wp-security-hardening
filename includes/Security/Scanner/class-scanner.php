<?php
namespace WP_Security\Security\Scanner;

use WP_Security\Utils\Logger;
use WP_Security\Security\QuarantineManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 'Direct access not permitted.' );
}

/**
 * Main security scanner class
 *
 * @package WP_Security\Security\Scanner
 */
class Scanner {
	/** @var Logger */
	private $logger;

	/** @var QuarantineManager */
	private $quarantine;

	/** @var array */
	private $results = array();

	/** @var array */
	private $patterns = array(
		'php_shell'         => '/(?:passthru|shell_exec|system|phpinfo|chmod|mkdir|fopen|readfile)\s*\(/',
		'eval_usage'        => '/eval\s*\(\s*(?:\$|base64_decode|gzinflate)/',
		'base64'            => '/base64_decode\s*\([^)]{20,}\)/',
		'iframe_injection'  => '/<iframe\s+[^>]*src\s*=\s*["\'][^"\']*["\'][^>]*>/',
		'js_eval'           => '/eval\s*\(\s*(?:unescape|String\.fromCharCode)/',
		'js_document_write' => '/document\.write\s*\(\s*(?:unescape|String\.fromCharCode)/',
	);

	/**
	 * Constructor
	 *
	 * @param Logger            $logger Logger instance
	 * @param QuarantineManager $quarantine Quarantine manager instance
	 */
	public function __construct( Logger $logger, QuarantineManager $quarantine ) {
		$this->logger     = $logger;
		$this->quarantine = $quarantine;
	}

	/**
	 * Run complete security scan
	 *
	 * @return array Scan results
	 * @throws \Exception If scan fails
	 */
	public function run(): array {
		$this->logger->info( 'Starting security scan' );
		$this->results = array();

		try {
			$this->handle_zero_byte_files();
			$this->scan_for_malware();
			$this->verify_core_files();

			update_option( 'wp_security_last_scan', current_time( 'mysql' ) );
			$this->logger->info( 'Scan completed successfully' );

			return $this->results;

		} catch ( \Exception $e ) {
			$this->logger->error( 'Scan failed: ' . $e->getMessage() );
			throw $e;
		}
	}

	/**
	 * Handle zero-byte files
	 *
	 * @return void
	 */
	private function handle_zero_byte_files(): void {
		$this->results['zero_byte_files'] = array();

		// Define directories to scan
		$scan_dirs = array(
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
			ABSPATH . 'wp-content/plugins',
			ABSPATH . 'wp-content/themes',
			WP_CONTENT_DIR,
		);

		// Define excluded paths
		$excluded_paths = array(
			'wp-content/uploads',
			'wp-content/cache',
			'wp-content/backup',
			'wp-content/debug.log',
			'node_modules',
			'vendor',
		);

		foreach ( $scan_dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			try {
				$iterator = new \RecursiveIteratorIterator(
					new \RecursiveDirectoryIterator( $dir, \RecursiveDirectoryIterator::SKIP_DOTS ),
					\RecursiveIteratorIterator::CHILD_FIRST
				);

				foreach ( $iterator as $file ) {
					// Skip if not a file or if in excluded path
					if ( ! $file->isFile() || $this->is_excluded_path( $file->getPathname(), $excluded_paths ) ) {
						continue;
					}

					// Only process PHP files and common web files
					$extension = strtolower( $file->getExtension() );
					if ( ! in_array( $extension, array( 'php', 'html', 'htm', 'js' ), true ) ) {
						continue;
					}

					// Check for zero-byte files
					if ( $file->getSize() === 0 ) {
						$path                               = wp_normalize_path( $file->getPathname() );
						$this->results['zero_byte_files'][] = $path;

						if ( 'php' === $extension ) {
							$this->quarantine->quarantine_file( $path, 'zero_byte_php' );
							$this->logger->warning( "Quarantined zero-byte PHP file: $path" );
						}
					}
				}
			} catch ( \Exception $e ) {
				$this->logger->error( 'Error scanning directory ' . $dir . ': ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Check if path should be excluded
	 *
	 * @param string $path File path to check
	 * @param array  $excluded_paths List of excluded paths
	 * @return bool
	 */
	private function is_excluded_path( string $path, array $excluded_paths ): bool {
		$normalized_path = wp_normalize_path( $path );

		foreach ( $excluded_paths as $excluded ) {
			if ( false !== strpos( $normalized_path, wp_normalize_path( $excluded ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Scan for malware in files
	 *
	 * @return void
	 */
	private function scan_for_malware(): void {
		$this->results['infected_files'] = array();

		foreach ( $this->get_scannable_files() as $file ) {
			try {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				$content = file_get_contents( $file );

				if ( false === $content ) {
					$this->logger->warning( "Could not read file: $file" );
					continue;
				}

				$threats = $this->analyze_file_content( $content, $file );

				if ( ! empty( $threats ) ) {
					$this->results['infected_files'][] = array(
						'file'    => $file,
						'threats' => $threats,
					);

					if ( $this->should_quarantine( $threats ) ) {
						$this->quarantine->quarantine_file( $file, 'malware_detected' );
					}
				}
			} catch ( \Exception $e ) {
				$this->logger->error( "Error scanning file {$file}: " . $e->getMessage() );
			}
		}
	}

	private function analyze_file_content( string $content, string $file ): array {
		$threats = array();

		// Check for malware patterns
		foreach ( $this->patterns as $type => $pattern ) {
			if ( preg_match( $pattern, $content, $matches ) ) {
				$threats[] = array(
					'type'     => $type,
					'match'    => $matches[0],
					'severity' => $this->get_threat_severity( $type ),
				);
			}
		}

		// Check for obfuscated code
		if ( $this->contains_obfuscated_code( $content ) ) {
			$threats[] = array(
				'type'     => 'obfuscated_code',
				'severity' => 'high',
			);
		}

		// Check for suspicious eval usage
		if ( $this->contains_suspicious_eval( $content ) ) {
			$threats[] = array(
				'type'     => 'suspicious_eval',
				'severity' => 'critical',
			);
		}

		return $threats;
	}

	private function get_threat_severity( string $type ): string {
		$severity_map = array(
			'php_shell'         => 'critical',
			'eval_usage'        => 'critical',
			'base64'            => 'high',
			'iframe_injection'  => 'medium',
			'js_eval'           => 'high',
			'js_document_write' => 'medium',
		);

		return $severity_map[ $type ] ?? 'medium';
	}

	private function contains_obfuscated_code( string $content ): bool {
		// Check for common obfuscation patterns
		$obfuscation_patterns = array(
			'/(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*=[\'"]\w+[\'"]\s*;[\s\n\r]*){4,}/',
			'/str_rot13\s*\(\s*base64_decode\s*\(/',
			'/gzinflate\s*\(\s*base64_decode\s*\(/',
		);

		foreach ( $obfuscation_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				return true;
			}
		}

		return false;
	}

	private function contains_suspicious_eval( string $content ): bool {
		$suspicious_patterns = array(
			'/eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
			'/eval\s*\(\s*base64_decode\s*\(/',
			'/eval\s*\(\s*gzinflate\s*\(/',
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				return true;
			}
		}

		return false;
	}

	private function should_quarantine( array $threats ): bool {
		foreach ( $threats as $threat ) {
			if ( ( $threat['severity'] ?? 'medium' ) === 'critical' ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Verify WordPress core files
	 *
	 * @return void
	 */
	private function verify_core_files(): void {
		$this->results['modified_core_files'] = array();

		$wp_version = get_bloginfo( 'version' );
		$checksums  = $this->get_core_checksums( $wp_version );

		if ( empty( $checksums ) ) {
			$this->logger->warning( 'Could not retrieve WordPress checksums' );
			return;
		}

		foreach ( $checksums as $file => $checksum ) {
			$file_path = ABSPATH . $file;

			if ( ! file_exists( $file_path ) ) {
				$this->results['modified_core_files'][] = array(
					'file'   => $file,
					'status' => 'missing',
				);
				continue;
			}

			if ( md5_file( $file_path ) !== $checksum ) {
				$this->results['modified_core_files'][] = array(
					'file'   => $file,
					'status' => 'modified',
				);
			}
		}
	}

	/**
	 * Get list of files to scan
	 *
	 * @return array List of file paths
	 */
	private function get_scannable_files(): array {
		$files           = array();
		$scan_extensions = array( 'php', 'js', 'html' );
		$excluded_dirs   = array( 'node_modules', 'vendor' );

		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( ABSPATH )
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}

			$path = $file->getPathname();
			$ext  = $file->getExtension();

			if ( ! in_array( $ext, $scan_extensions, true ) ) {
				continue;
			}

			foreach ( $excluded_dirs as $excluded ) {
				if ( false !== strpos( $path, "/$excluded/" ) ) {
					continue 2;
				}
			}

			$files[] = $path;
		}

		return $files;
	}

	/**
	 * Get WordPress core checksums
	 *
	 * @param string $version WordPress version
	 * @return array Checksums array
	 */
	private function get_core_checksums( string $version ): array {
		$url      = "https://api.wordpress.org/core/checksums/1.0/?version=$version&locale=en_US";
		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			return array();
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return $data['checksums'] ?? array();
	}
}
