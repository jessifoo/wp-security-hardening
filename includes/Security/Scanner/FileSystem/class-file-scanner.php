<?php
namespace WP_Security\Scanner\FileSystem;

use Psr\Log\LoggerInterface;

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

/**
 * Scanner for filesystem threats
 */
class FileScanner {
	/** @var array */
	private $fileTypes;

	/** @var array */
	private $excludePaths;

	/** @var int */
	private $maxFileSize;

	/** @var LoggerInterface */
	private $logger;

	/** @var array */
	private $config;

	/** @var bool */
	private $shouldPause = false;

	/** @var array Sensitive file patterns */
	private const SENSITIVE_FILES = array(
		'wp-config.php' => array(
			'type'     => 'config',
			'severity' => 'high',
		),
		'.htaccess'     => array(
			'type'     => 'config',
			'severity' => 'medium',
		),
		'php.ini'       => array(
			'type'     => 'config',
			'severity' => 'medium',
		),
		'.env'          => array(
			'type'     => 'environment',
			'severity' => 'high',
		),
		'debug.log'     => array(
			'type'     => 'log',
			'severity' => 'medium',
		),
	);

	/** @var array Malware signature patterns */
	private const MALWARE_PATTERNS = array(
		'base64_decode_exec'    => array(
			'pattern'     => 'base64_decode\s*\([^)]*\)\s*\(\s*[\'"][^\'"]*[\'"]\s*\)',
			'severity'    => 'critical',
			'description' => 'Base64 encoded execution detected',
		),
		'eval_base64'           => array(
			'pattern'     => 'eval\s*\(\s*base64_decode\s*\([^)]+\)\s*\)',
			'severity'    => 'critical',
			'description' => 'Eval with base64 decode detected',
		),
		'shell_exec'            => array(
			'pattern'     => '(shell_exec|system|passthru|exec|popen)\s*\(',
			'severity'    => 'critical',
			'description' => 'Shell command execution detected',
		),
		'remote_file_inclusion' => array(
			'pattern'     => '(include|require)(_once)?\s*[\'"](https?|ftp)',
			'severity'    => 'high',
			'description' => 'Remote file inclusion detected',
		),
		'php_uname'             => array(
			'pattern'     => 'php_uname\s*\(',
			'severity'    => 'medium',
			'description' => 'System information disclosure attempt',
		),
	);

	/** @var array File patterns to scan */
	private const FILE_PATTERNS = array(
		'php'       => array( '\.php$', '\.phtml$' ),
		'js'        => array( '\.js$' ),
		'suspected' => array( '\.suspected$', '\.quarantine$' ),
		'backdoor'  => array( '\.php\.[0-9]+$', '\.php\.suspected$' ),
	);

	/**
	 * Constructor
	 *
	 * @param LoggerInterface $logger Logger instance
	 * @param array           $config Optional configuration
	 */
	public function __construct( LoggerInterface $logger, array $config = array() ) {
		$this->logger = $logger;
		$this->config = $config;
		$this->initialize();
	}

	/**
	 * Initialize scanner configuration
	 */
	private function initialize(): void {
		if ( ! function_exists( 'finfo_open' ) ) {
			throw new \RuntimeException( 'PHP fileinfo extension required' );
		}

		$this->fileTypes    = $this->config['file_types'] ?? self::FILE_PATTERNS;
		$this->excludePaths = $this->config['exclude_paths'] ?? array( 'wp-admin', 'wp-includes' );
		$this->maxFileSize  = $this->config['max_file_size'] ?? 10 * 1024 * 1024; // 10MB default
	}

	/**
	 * Start scanning a target directory
	 *
	 * @param string $target Directory to scan
	 * @return array Scan results
	 */
	public function scan( string $target ): array {
		$result = array(
			'status'   => 'scanning',
			'stats'    => array(
				'items_scanned' => 0,
				'threats_found' => 0,
				'warnings'      => 0,
			),
			'threats'  => array(),
			'warnings' => array(),
			'metadata' => array(),
		);

		try {
			if ( ! is_dir( $target ) ) {
				throw new \RuntimeException( "Target directory not found: $target" );
			}

			$files                             = $this->getFilesToScan( $target );
			$result['metadata']['total_files'] = count( $files );

			foreach ( $files as $file ) {
				if ( $this->shouldPause ) {
					$result['metadata']['scan_paused'] = true;
					break;
				}

				$this->scanFile( $file, $result );
			}

			$result['status'] = 'completed';
			return $result;

		} catch ( \Exception $e ) {
			$this->logger->error( 'File scan error: ' . $e->getMessage() );
			$result['status'] = 'error';
			$result['error']  = $e->getMessage();
			return $result;
		}
	}

	/**
	 * Pause the current scan
	 */
	public function pauseScan(): void {
		$this->shouldPause = true;
	}

	/**
	 * Resume a paused scan
	 */
	public function resumeScan(): void {
		$this->shouldPause = false;
	}

	/**
	 * Get list of files to scan
	 *
	 * @param string $directory Directory to scan
	 * @return array
	 */
	private function getFilesToScan( string $directory ): array {
		$files    = array();
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $directory, \RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( $this->shouldScanFile( $file ) ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	/**
	 * Check if file should be scanned
	 *
	 * @param \SplFileInfo $file File to check
	 * @return bool
	 */
	private function shouldScanFile( \SplFileInfo $file ): bool {
		// Skip directories and links
		if ( ! $file->isFile() || $file->isLink() ) {
			return false;
		}

		// Check file size
		if ( $file->getSize() > $this->maxFileSize ) {
			return false;
		}

		// Check excluded paths
		foreach ( $this->excludePaths as $excludePath ) {
			if ( strpos( $file->getPathname(), $excludePath ) !== false ) {
				return false;
			}
		}

		// Check file types
		$extension = strtolower( $file->getExtension() );
		foreach ( $this->fileTypes as $patterns ) {
			foreach ( (array) $patterns as $pattern ) {
				if ( preg_match( "/$pattern/i", $file->getBasename() ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Scan individual file
	 *
	 * @param string $filepath File to scan
	 * @param array  &$result  Scan result array
	 */
	private function scanFile( string $filepath, array &$result ): void {
		++$result['stats']['items_scanned'];

		// Check file permissions
		$perms = fileperms( $filepath ) & 0777;
		if ( $perms > 0644 ) {
			$result['warnings'][] = array(
				'type'    => 'excessive_permissions',
				'file'    => $filepath,
				'details' => array( 'permissions' => sprintf( '%04o', $perms ) ),
			);
			++$result['stats']['warnings'];
		}

		// Check if it's a sensitive file
		$basename = basename( $filepath );
		if ( isset( self::SENSITIVE_FILES[ $basename ] ) ) {
			$result['warnings'][] = array(
				'type'    => 'sensitive_file',
				'file'    => $filepath,
				'details' => self::SENSITIVE_FILES[ $basename ],
			);
			++$result['stats']['warnings'];
		}

		// Scan file content
		$content = @file_get_contents( $filepath );
		if ( $content === false ) {
			$result['warnings'][] = array(
				'type'    => 'unreadable_file',
				'file'    => $filepath,
				'details' => array( 'error' => error_get_last()['message'] ?? 'Unknown error' ),
			);
			++$result['stats']['warnings'];
			return;
		}

		// Check for malware patterns
		foreach ( self::MALWARE_PATTERNS as $name => $info ) {
			if ( preg_match( "/{$info['pattern']}/i", $content ) ) {
				$result['threats'][] = array(
					'type'    => $name,
					'file'    => $filepath,
					'details' => array(
						'severity'    => $info['severity'],
						'description' => $info['description'],
					),
				);
				++$result['stats']['threats_found'];
			}
		}

		// Check for obfuscation
		if ( $this->isLikelyObfuscated( $content ) ) {
			$result['warnings'][] = array(
				'type'    => 'possible_obfuscation',
				'file'    => $filepath,
				'details' => array( 'entropy' => $this->calculateEntropy( $content ) ),
			);
			++$result['stats']['warnings'];
		}
	}

	/**
	 * Check if content is likely obfuscated
	 *
	 * @param string $content Content to check
	 * @return bool
	 */
	private function isLikelyObfuscated( string $content ): bool {
		// Remove comments and whitespace
		$content = preg_replace( '/\/\*.*?\*\/|\/\/.*?$/m', '', $content );
		$content = preg_replace( '/\s+/', '', $content );

		// Calculate entropy
		$entropy = $this->calculateEntropy( $content );

		// High entropy often indicates obfuscation
		return $entropy > 5.7;
	}

	/**
	 * Calculate Shannon entropy of content
	 *
	 * @param string $content Content to analyze
	 * @return float
	 */
	private function calculateEntropy( string $content ): float {
		$frequencies = array_count_values( str_split( $content ) );
		$length      = strlen( $content );
		$entropy     = 0.0;

		foreach ( $frequencies as $count ) {
			$probability = $count / $length;
			$entropy    -= $probability * log( $probability, 2 );
		}

		return $entropy;
	}
}
